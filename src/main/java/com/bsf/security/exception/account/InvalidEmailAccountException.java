package com.bsf.security.exception.account;

import com.bsf.security.exception._common.BTException;

public class InvalidEmailAccountException  extends BTException {
    public InvalidEmailAccountException(String message) {
        super(message);
    }
}
