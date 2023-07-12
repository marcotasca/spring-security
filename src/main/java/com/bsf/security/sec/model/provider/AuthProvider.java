package com.bsf.security.sec.model.provider;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.Arrays;
import java.util.Optional;

@RequiredArgsConstructor
public enum AuthProvider {
    LOCAL(1),
    GOOGLE(2);

    @Getter
    private final int providerId;

    public static Optional<AuthProvider> findByProviderName(String providerName) {
        return Arrays.stream(AuthProvider.values())
                .filter(authProvider -> authProvider.name().equalsIgnoreCase(providerName))
                .findFirst();
    }

}
