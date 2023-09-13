package com.bsf.security.dao.mapstruct.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record AccountDto (
        @JsonProperty("first_name") String firstname,
        @JsonProperty("last_name") String lastname,
        @JsonProperty("email") String email,
        @JsonProperty("status") String status
) {}
