package com.bsf.security.exception.account;

import com.bsf.security.exception._common.BTException;

import java.util.List;

public class InvalidPasswordAccountException extends BTException {
    public InvalidPasswordAccountException(String messages, Object[] args) {
        super(messages, args);
    }
}
