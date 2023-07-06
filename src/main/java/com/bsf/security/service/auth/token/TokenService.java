package com.bsf.security.service.auth.token;

import com.bsf.security.sec.model.account.Account;
import com.bsf.security.sec.model.token.Token;
import com.bsf.security.sec.model.token.TokenScopeCategoryEnum;
import com.bsf.security.sec.model.token.TokenTypeEnum;

import java.util.Optional;

public interface TokenService {

    Optional<Token> findByAccountIdAndTokenScopeCategoryId(int accountId, int tokenScopeCategoryId);

    void saveUserToken(
            Account account,
            String accessToken,
            String refreshToken,
            String ipAddress,
            TokenTypeEnum tokenType,
            TokenScopeCategoryEnum tokenScopeCategoryEnum
    );

    void delete(Token token);

}
