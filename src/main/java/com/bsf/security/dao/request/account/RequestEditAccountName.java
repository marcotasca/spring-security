package com.bsf.security.dao.request.account;

import com.fasterxml.jackson.annotation.JsonProperty;

public record RequestEditAccountName(
        @JsonProperty("first_name") String firstName,
        @JsonProperty("last_name") String lastName
) {}
