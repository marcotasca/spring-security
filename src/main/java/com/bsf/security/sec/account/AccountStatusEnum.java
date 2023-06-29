package com.bsf.security.sec.account;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public enum AccountStatusEnum {
    Pending(1),
    Enabled(2),
    Disabled(3);

    @Getter
    private final int statusId;

}
