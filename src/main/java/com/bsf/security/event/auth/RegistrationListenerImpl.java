package com.bsf.security.event.auth;

import com.bsf.security.service.email.EmailService;
import com.bsf.security.util.UtilService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.event.EventListener;
import org.springframework.core.io.ClassPathResource;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.util.StreamUtils;

import java.nio.charset.StandardCharsets;

@Slf4j
@Component
public class RegistrationListenerImpl implements RegistrationService {

    @Autowired
    private EmailService emailService;

    @Autowired
    private UtilService utilService;

    @Value("${application.support.email}")
    private String supportEmail;

    @Value("${application.support.phone}")
    private String supportPhone;

    @Value("${application.name}")
    private String applicationName;

    @Value("${application.email.no-reply}")
    private String noReply;

    @Async
    @Override
    @EventListener
    public void handleOnRegistrationEvent(OnRegistrationEvent event) {
        log.info("[BTDoctor::Registration] Account -> {}", event.getAccount());

        String text = "";
        try {
            ClassPathResource resource = new ClassPathResource("/static/email/registration.html");
            byte[] fileContent = StreamUtils.copyToByteArray(resource.getInputStream());
            text = new String(fileContent, StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
        }

        String linkToVerify = event.getAppUrl() + "/api/v1/auth/register/verify/" + event.getRegistrationToken();
        text = text
                .replace("{{registration.name}}", event.getAccount().getFirstname())
                .replace("{{registration.url}}", linkToVerify)
                .replace("{{registration.support.phone}}", supportPhone)
                .replace("{{registration.support.email}}", supportEmail);

        emailService.sendSimpleMessage(
                noReply,
                applicationName,
                event.getAccount().getEmail(),
                "Confirm Your Registration",
                text
        );
    }

    @Async
    @Override
    @EventListener
    public void handleOnRegistrationCompletedEvent(OnRegistrationCompletedEvent event) {
        log.info("[BTDoctor::RegistrationCompleted] Account -> {}", event.getAccount());

        String text = "";
        try {
            ClassPathResource resource = new ClassPathResource("/static/email/registration_completed.html");
            byte[] fileContent = StreamUtils.copyToByteArray(resource.getInputStream());
            text = new String(fileContent, StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
        }

        String fullName = event.getAccount().getFirstname() + " " + event.getAccount().getLastname();
        text = text
                .replace("{{registration.name}}", event.getAccount().getFirstname())
                .replace("{{registration.full_name}}", fullName)
                .replace("{{registration.username}}", event.getAccount().getEmail());

        emailService.sendSimpleMessage(
                noReply,
                applicationName,
                event.getAccount().getEmail(),
                "Registration confirmed",
                text
        );
    }

}
