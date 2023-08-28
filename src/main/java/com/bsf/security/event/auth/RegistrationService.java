package com.bsf.security.event.auth;

public interface RegistrationService {
    void handleOnRegistrationEvent(OnRegistrationEvent event);
    void handleOnRegistrationCompletedEvent(OnRegistrationCompletedEvent event);
}
