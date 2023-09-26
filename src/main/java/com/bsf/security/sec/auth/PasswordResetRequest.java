package com.bsf.security.sec.auth;

import com.fasterxml.jackson.annotation.JsonProperty;

public record PasswordResetRequest (
    String password,
    @JsonProperty("confirm_password") String confirmPassword
) {}
