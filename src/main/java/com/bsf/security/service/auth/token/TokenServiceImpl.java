package com.bsf.security.service.auth.token;

import com.bsf.security.sec.config.JwtService;
import com.bsf.security.sec.model.account.Account;
import com.bsf.security.sec.model.token.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class TokenServiceImpl implements TokenService {

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
        // Estraggo la data di scadenza
        Date accessTokenExpiration = jwtService.extractExpiration(accessToken);

        // Creo il token per l'utente
        var token = Token
                .builder()
                .account(account)
                .accessToken(accessToken)
                .tokenType(new TokenType(tokenType.getTokenTypeId()))
                .accessTokenExpiration(accessTokenExpiration)
                .tokenScopeCategory(new TokenScopeCategory(tokenScopeCategoryEnum.getTokenScopeCategoryId()))
                .ipAddress(ipAddress)
                .build();

        // Imposto il refresh token se non nullo
        if(refreshToken != null) {
            Date refreshTokenExpiration = jwtService.extractExpiration(refreshToken);
            token.setRefreshToken(refreshToken);
            token.setRefreshTokenExpiration(refreshTokenExpiration);
        }

        // Salvo il token per l'utente
        tokenRepository.save(token);
    }

}
