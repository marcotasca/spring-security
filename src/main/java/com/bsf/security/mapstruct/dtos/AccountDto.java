package com.bsf.security.mapstruct.dtos;

import com.fasterxml.jackson.annotation.JsonProperty;

public record AccountDto (
        @JsonProperty("first_name") String firstname,
        @JsonProperty("last_name") String lastname,
        @JsonProperty("email") String email,
        @JsonProperty("status") String status
) {}
