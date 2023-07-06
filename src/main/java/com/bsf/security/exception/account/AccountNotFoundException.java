package com.bsf.security.exception.account;

import com.bsf.security.exception._common.BTException;

public class AccountNotFoundException extends BTException {
    public AccountNotFoundException(String message) {
        super(message);
    }
}
