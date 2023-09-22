package com.bsf.security.event.auth;

import com.bsf.security.sec.model.account.Account;
import org.springframework.context.ApplicationEvent;

public class OnResetAccountCompletedEvent extends ApplicationEvent {

    private final Account account;

    public OnResetAccountCompletedEvent(Object source, final Account account) {
        super(source);
        this.account = account;
    }

    public Account getAccount() {
        return account;
    }

}
