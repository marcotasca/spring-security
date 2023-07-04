package com.bsf.security.sec.auth;

import com.bsf.security.sec.config.JwtService;
import com.bsf.security.sec.model.account.Account;
import com.bsf.security.sec.model.token.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class TokenService {

    @Autowired
    JwtService jwtService;

    @Autowired
    TokenRepository tokenRepository;

    public void saveUserToken(
            Account account,
            String accessToken,
            String refreshToken,
            String ipAddress,
            TokenTypeEnum tokenType,
            TokenScopeCategoryEnum tokenScopeCategoryEnum
    ) {
        // Estraggo le date di scadenza
        Date accessTokenExpiration = jwtService.extractExpiration(accessToken);
        Date refreshTokenExpiration = jwtService.extractExpiration(refreshToken);

        // Creo il token per l'utente
        var token = Token
                .builder()
                .account(account)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType(new TokenType(tokenType.getTokenTypeId()))
                .accessTokenExpiration(accessTokenExpiration)
                .refreshTokenExpiration(refreshTokenExpiration)
                .tokenScopeCategory(new TokenScopeCategory(tokenScopeCategoryEnum.getTokenScopeCategoryId()))
                .ipAddress(ipAddress)
                .build();

        // Salvo il token per l'utente
        tokenRepository.save(token);
    }

}
