package com.bsf.security.exception.account;

import lombok.Getter;

import java.util.List;

public class InvalidPasswordAccountListException extends RuntimeException {

    @Getter
    private final List<InvalidPasswordAccountException> exceptions;

    public InvalidPasswordAccountListException(List<InvalidPasswordAccountException> exceptions) {
        this.exceptions = exceptions;
    }

}
