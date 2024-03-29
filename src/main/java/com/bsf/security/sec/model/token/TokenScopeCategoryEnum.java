package com.bsf.security.sec.model.token;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
public enum TokenScopeCategoryEnum {
    BTD_RW(1),
    BTD_REGISTRATION(2),
    BTD_RESET(3);

    @Getter
    private final int tokenScopeCategoryId;

}
