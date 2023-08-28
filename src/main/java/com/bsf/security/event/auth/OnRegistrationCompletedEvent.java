package com.bsf.security.event.auth;

import com.bsf.security.sec.model.account.Account;
import org.springframework.context.ApplicationEvent;

public class OnRegistrationCompletedEvent extends ApplicationEvent {

    private final Account account;

    public OnRegistrationCompletedEvent(Object source, final Account account) {
        super(source);
        this.account = account;
    }

    public Account getAccount() {
        return account;
    }

}
