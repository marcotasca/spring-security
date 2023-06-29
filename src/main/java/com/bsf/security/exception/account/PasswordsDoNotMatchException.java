package com.bsf.security.exception.account;

import com.bsf.security.exception._common.BTException;

public class PasswordsDoNotMatchException extends BTException {

    public PasswordsDoNotMatchException(String message) {
        super(message);
    }

}
