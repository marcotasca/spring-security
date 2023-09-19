package com.bsf.security.dao.request.account;

import com.fasterxml.jackson.annotation.JsonProperty;

public record RequestEditAccountPassword (
        @JsonProperty("current_password") String currentPassword,
        @JsonProperty("password") String password,
        @JsonProperty("confirm_password") String confirmPassword
) {}
