package com.bsf.security.exception.account;

import com.bsf.security.exception._common.BTException;

public class DuplicateAccountException extends BTException {
    public DuplicateAccountException() {
        super();
    }

    public DuplicateAccountException(String message) {
        super(message);
    }
}
