package com.bsf.security.event.auth;

import com.bsf.security.sec.model.account.Account;
import org.springframework.context.ApplicationEvent;

public class OnResetAccountEvent extends ApplicationEvent {

    private final Account account;

    private final String resetToken;

    private final String appUrl;

    public OnResetAccountEvent(Object source, final Account account, String resetToken, String appUrl) {
        super(source);
        this.account = account;
        this.resetToken = resetToken;
        this.appUrl = appUrl;
    }

    public Account getAccount() {
        return account;
    }

    public String getResetToken() {
        return resetToken;
    }

    public String getAppUrl() {
        return appUrl;
    }
}
