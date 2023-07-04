package com.bsf.security.sec.model;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public enum AuthProvider {
    LOCAL(1),
    GOOGLE(2);

    @Getter
    private final int providerId;

}
