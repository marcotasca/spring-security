package com.bsf.security.sec.model.token;

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
