	/**
 * Create Member
 *
 * @param    array               $values             Values from form
 * @param    array               $profileFields      Profile field values from registration
 * @param    array|NULL          $postBeforeRegister    The row from core_post_before_registering if applicable
 * @param    \IPS\Helpers\Form    $form               The form object
 * @return  \IPS\Member|bool     Returns member object if registration is successful, otherwise false
 */
public static function _createMember($values, $profileFields, $postBeforeRegister, &$form)
{
    /* Check if email is provided and not empty */
    if (empty($values['email_address'])) {
        \IPS\Output::i()->error('Email address is required.', 'email_required_error', 403, '');
        return false;
    }

    /* Check for disposable email */
    if (static::checkDisposableEmail($values['email_address'])) {
        \IPS\Output::i()->error('Disposable email addresses are not allowed.', 'disposable_email_error', 403, '');
        return false;
    }

    /* Create */
    $member = new \IPS\Member;
    $member->name = $values['username'];
    $member->email = $values['email_address'];
    $member->setLocalPassword($values['password']);
    $member->allow_admin_mails = $values['reg_admin_mails'];
    $member->member_group_id = \IPS\Settings::i()->member_group;
    $member->members_bitoptions['view_sigs'] = true;
    $member->last_visit = time();

    if (isset(\IPS\Request::i()->cookie['language']) && \IPS\Request::i()->cookie['language']) {
        $member->language = \IPS\Request::i()->cookie['language'];
    } elseif (isset($_SERVER['HTTP_ACCEPT_LANGUAGE'])) {
        $member->language = \IPS\Lang::autoDetectLanguage($_SERVER['HTTP_ACCEPT_LANGUAGE']);
    }

    if (\IPS\Settings::i()->allow_reg != 'disabled') {
        /* Initial Save */
        $member->save();

        /* This looks a bit weird, but the extensions expect an account to exist at this point, so we'll let the system save it now, then do what we need to do, then save again */
        foreach (\IPS\Member\ProfileStep::loadAll() as $step) {
            $extension = $step->extension;
            $extension::formatFormValues($values, $member, $form);
        }
    }

    /* Save anything the profile extensions did */
    $member->save();

    /* Security Questions */
    if (\IPS\Settings::i()->security_questions_enabled && \in_array(\IPS\Settings::i()->security_questions_prompt, array('register', 'optional'))) {
        if (isset($values['security_questions_optout_title'])) {
            $member->members_bitoptions['security_questions_opt_out'] = true;

            /* Log MFA Opt-out */
            $member->logHistory('core', 'mfa', array('handler' => 'questions', 'enable' => false, 'optout' => true));
        } else {
            $answers = array();

            foreach ($values as $k => $v) {
                if (preg_match('/^security_question_q_(\d+)$/', $k, $matches)) {
                    $answers[$v] = array(
                        'answer_question_id' => $v,
                        'answer_member_id' => $member->member_id,
                        'answer_answer' => \IPS\Text\Encrypt::fromPlaintext($values['security_question_a_' . $matches[1]])->tag()
                    );
                }
            }

            if (\count($answers)) {
                \IPS\Db::i()->insert('core_security_answers', $answers);
            }

            $member->members_bitoptions['has_security_answers'] = true;

            /* Log MFA Enable */
            $member->logHistory('core', 'mfa', array('handler' => 'questions', 'enable' => true));
        }
        $member->save();
    }

    /* Cycle profile fields */
    foreach ($profileFields as $id => $fieldValue) {
        $field = \IPS\core\ProfileFields\Field::loadWithMember(mb_substr($id, 6), null, null, null);
        if ($field->type == 'Editor') {
            $field->claimAttachments($member->member_id);
        }
    }

    /* Save custom field values */
    \IPS\Db::i()->replace('core_pfields_content', array_merge(array('member_id' => $member->member_id), $profileFields));

    /* Log that we gave consent for admin emails */
    $member->logHistory('core', 'admin_mails', array('enabled' => (bool) $member->allow_admin_mails));

    /* Log that we gave consent for terms and privacy */
    if (\IPS\Settings::i()->privacy_type != 'none') {
        $member->logHistory('core', 'terms_acceptance', array('type' => 'privacy'));
    }

    $member->logHistory('core', 'terms_acceptance', array('type' => 'terms'));

    /* Handle validation */
    $member->postRegistration(false, false, $postBeforeRegister, static::_refUrl());

    /* Save and return */
    return $member;
}

/**
 * Check if an email address is disposable
 *
 * @param string $email The email address to check
 * @return bool True if the email is disposable, otherwise false
 */
protected static function checkDisposableEmail($email)
{
    $api_url = 'https://api.api-aries.online/v1/checkers/proxy/email/?email=' . urlencode($email);
    $ch = curl_init($api_url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array(
        'Type: TOKEN TYPE',  // learn more: https://support.api-aries.online/hc/articles/1/3/3/email-checker
        'APITOKEN: API KEY' // learn more: https://support.api-aries.online/hc/articles/1/3/3/email-checker
    ));
    $response = curl_exec($ch);
    $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    echo "Response code: " . $httpcode . PHP_EOL;
    echo "Response: " . $response . PHP_EOL;

    if ($httpcode === 200) {
        $data = json_decode($response, true);
        if ($data && isset($data['disposable']) && strtolower($data['disposable']) === 'yes') {
            return true;
        }
    }
    return false;
}
