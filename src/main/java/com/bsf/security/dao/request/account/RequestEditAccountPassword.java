package com.bsf.security.dao.request.account;

import com.fasterxml.jackson.annotation.JsonProperty;

public record RequestEditAccountPassword (String password, @JsonProperty("confirm_password") String confirmPassword) {}
