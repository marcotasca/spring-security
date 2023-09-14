package com.bsf.security.service.auth.token;

import com.bsf.security.sec.config.JwtService;
import com.bsf.security.sec.model.account.Account;
import com.bsf.security.sec.model.token.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;
import java.util.Optional;

@Service
public class TokenServiceImpl implements TokenService {

    @Autowired
    JwtService jwtService;

    @Autowired
    TokenRepository tokenRepository;

    @Override
    public Optional<Token> findByAccessToken(String accessToken) {
        return tokenRepository.findByAccessToken(accessToken);
    }

    @Override
    public Optional<Token> findByRefreshToken(String refreshToken) {
        return tokenRepository.findByRefreshToken(refreshToken);
    }

    @Override
    public Optional<Token> findByAccountIdAndTokenScopeCategoryId(int accountId, int tokenScopeCategoryId) {
        return tokenRepository.findByAccountIdAndTokenScopeCategoryId(accountId, tokenScopeCategoryId);
    }

    public Token saveUserToken(
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
        return tokenRepository.save(token);
    }

    @Override
    public void delete(Token token) {
        tokenRepository.delete(token);
    }

    @Override
    public List<Token> findAllValidTokenByUser(Integer accountId) {
        return tokenRepository.findAllByAccountId(accountId);
    }

    @Override
    public void revokeAllAccountTokens(Account account) {
        // Recupero tutti i token validi dell'account
        var validAccountTokens = findAllValidTokenByUser(account.getId());

        // Se non ce ne sono esco dalla funzione
        if(validAccountTokens.isEmpty()) return;

        // Revoco ogni token dell'utente
        validAccountTokens.forEach(this::delete);
    }

}
