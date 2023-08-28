package com.bsf.security.service.email;

public interface EmailService {
    void sendSimpleMessage(String from, String fromPersonal, String to, String subject, String text);
}
