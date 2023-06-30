package com.bsf.security.sec.model.token;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
public enum TokenScopeCategoryEnum {
    BTD_REGISTRATION(1),
    BTD_RW(2);

    @Getter
    private final int tokenScopeCategoryId;

}
