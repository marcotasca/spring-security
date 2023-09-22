package com.bsf.security.event.auth;

public interface AuthListenerService {
    void handleOnRegistrationEvent(OnRegistrationEvent event);
    void handleOnRegistrationCompletedEvent(OnRegistrationCompletedEvent event);
    void handleOnResetAccountEvent(OnResetAccountEvent event);
    void handleOnResetAccountCompletedEvent(OnResetAccountCompletedEvent event);
}
