package com.bsf.security.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.stereotype.Component;

import java.util.Properties;

@Component
public class SpringMailConfiguration {

    @Value("${application.email.host}")
    private String host;

    @Value("${application.email.port}")
    private int port;

    @Value("${application.email.username}")
    private String username;

    @Value("${application.email.password}")
    private String password;

    @Value("${application.email.protocol}")
    private String protocol;

    @Value("${application.email.smtp.auth}")
    private String smtpAuth;

    @Value("${application.email.smtp.starttls.enable}")
    private String smtpStartTlsEnable;

    @Value("${application.email.debug}")
    private String debug;

    @Bean
    public JavaMailSender getJavaMailSender() {
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        mailSender.setHost(host);
        mailSender.setPort(port);

        mailSender.setUsername(username);
        mailSender.setPassword(password);

        Properties props = mailSender.getJavaMailProperties();
        props.put("mail.transport.protocol", protocol);
        props.put("mail.smtp.auth", smtpAuth);
        props.put("mail.smtp.starttls.enable", smtpStartTlsEnable);
        props.put("mail.debug", debug);

        return mailSender;
    }

}
