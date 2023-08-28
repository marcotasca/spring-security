package com.bsf.security.event.auth;

import com.bsf.security.sec.model.account.Account;
import org.springframework.context.ApplicationEvent;

public class OnRegistrationEvent extends ApplicationEvent {

    private final Account account;

    private final String registrationToken;

    private final String appUrl;

    public OnRegistrationEvent(Object source, final Account account, final String registrationToken, final String appUrl) {
        super(source);
        this.account = account;
        this.registrationToken = registrationToken;
        this.appUrl = appUrl;
    }

    public Account getAccount() {
        return account;
    }

    public String getRegistrationToken() {
        return registrationToken;
    }

    public String getAppUrl() {
        return appUrl;
    }
}