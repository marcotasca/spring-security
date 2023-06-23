package com.bsf.security.sec.token;

public enum TokenTypeEnum {
    BEARER(1);

    private final int tokenTypeId;

    TokenTypeEnum(int tokenTypeId) {
        this.tokenTypeId = tokenTypeId;
    }

    public int getTokenTypeId() {
        return tokenTypeId;
    }
}
