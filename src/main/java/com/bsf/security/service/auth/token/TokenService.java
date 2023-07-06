package com.bsf.security.service.auth.token;

import com.bsf.security.sec.model.account.Account;
import com.bsf.security.sec.model.token.TokenScopeCategoryEnum;
import com.bsf.security.sec.model.token.TokenTypeEnum;

public interface TokenService {

    void saveUserToken(
            Account account,
            String accessToken,
            String refreshToken,
            String ipAddress,
            TokenTypeEnum tokenType,
            TokenScopeCategoryEnum tokenScopeCategoryEnum
    );

}
