package com.bsf.security.exception.security.jwt;

import com.bsf.security.exception._common.BTException;

public class SecurityJWTException extends BTException {

    public SecurityJWTException(String message) {
        super(message);
    }

    public SecurityJWTException(String message, Object[] args) {
        super(message, args);
    }

}
