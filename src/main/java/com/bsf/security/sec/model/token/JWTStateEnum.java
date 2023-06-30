package com.bsf.security.sec.model.token;

public enum JWTStateEnum {
    JWT_EXPIRED,
    TOKEN_NULL_EMPTY_OR_WHITESPACE,
    JWT_INVALID,
    JWT_NOT_SUPPORTED,
    SIGNATURE_VALIDATION_FAILED;

}
