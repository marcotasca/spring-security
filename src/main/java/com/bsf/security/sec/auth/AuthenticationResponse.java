package com.bsf.security.sec.auth;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationResponse {

    @JsonProperty("access_token")
    public String accessToken;

    @JsonProperty("access_token_expiration_date")
    public Date accessTokenExpirationDate;

    @JsonProperty("refresh_token")
    public String refreshToken;

    @JsonProperty("refresh_token_expiration_date")
    public Date refreshTokenExpirationDate;

}
