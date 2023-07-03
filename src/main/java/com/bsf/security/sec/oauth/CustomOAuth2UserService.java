package com.bsf.security.sec.oauth;

import com.bsf.security.exception.security.OAuth2AuthenticationProcessingException;
import com.bsf.security.sec.model.AuthProvider;
import com.bsf.security.sec.model.account.*;
import com.bsf.security.sec.oauth.user.GoogleOAuth2UserInfo;
import com.bsf.security.sec.oauth.user.OAuth2UserInfo;
import com.bsf.security.sec.oauth.user.OAuth2UserInfoFactory;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final AccountRepository accountRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);

        try {
            return processOAuth2User(oAuth2UserRequest, oAuth2User);
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) {
        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(
                oAuth2UserRequest.getClientRegistration().getRegistrationId(), oAuth2User.getAttributes()
        );

        if(oAuth2UserInfo.getEmail() != null && !oAuth2UserInfo.getEmail().isEmpty()) {
            throw new OAuth2AuthenticationProcessingException("Email not found from OAuth2 provider");
        }

        Optional<Account> accountOptional = accountRepository.findByEmail(oAuth2UserInfo.getEmail());
        Account account;
        String authProvider = oAuth2UserRequest.getClientRegistration().getRegistrationId();

        if(accountOptional.isPresent()) {
            account = accountOptional.get();
            if(!account.getProvider().equals(authProvider)) {
                throw new OAuth2AuthenticationProcessingException("Looks like you're signed up with " +
                        account.getProvider() + " account. Please use your " + account.getProvider() +
                        " account to login.");
            }
            //account = updateExistingUser(account, oAuth2UserInfo);
        } else {
            if(AuthProvider.GOOGLE.name().equals(authProvider)) account = registerNewUser(oAuth2UserRequest, (GoogleOAuth2UserInfo) oAuth2UserInfo);
            else account = new Account();
        }

        account.setAttributes(oAuth2User.getAttributes());
        return account;
    }

    private Account registerNewUser(OAuth2UserRequest oAuth2UserRequest, GoogleOAuth2UserInfo googleOAuth2UserInfo) {
        var accountStatusId = googleOAuth2UserInfo.isEmailVerified() ?
                AccountStatusEnum.Enabled : AccountStatusEnum.Pending;

        return Account
                .builder()
                .firstname(googleOAuth2UserInfo.getGivenName())
                .lastname(googleOAuth2UserInfo.getFamilyName())
                .email(googleOAuth2UserInfo.getEmail())
                .password(null)
                .role(new Role(RoleEnum.USER.getRoleId()))
                .createdAt(LocalDateTime.now())
                .status(new AccountStatus(accountStatusId.getStatusId()))
                .provider(oAuth2UserRequest.getClientRegistration().getRegistrationId())
                .build();
    }

    private Account updateExistingUser(Account existingAccount, OAuth2UserInfo oAuth2UserInfo) {
//        oAuth2UserInfo.get
//        existingAccount.setna(oAuth2UserInfo.getName());
//        existingAccount.setImageUrl(oAuth2UserInfo.getImageUrl());
        return accountRepository.save(existingAccount);
    }

}

