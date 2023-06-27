package com.bsf.security.config;

import com.bsf.security.sec.account.Role;
import com.bsf.security.sec.auth.AuthenticationService;
import com.bsf.security.sec.auth.RegisterRequest;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.i18n.SessionLocaleResolver;

import java.util.Locale;

@Component
public class BeanConfiguration {

    @Bean
    public LocaleResolver localeResolver() {
        SessionLocaleResolver slr = new SessionLocaleResolver();
        slr.setDefaultLocale(Locale.US);
        return slr;
    }

    @Bean
    public CommandLineRunner commandLineRunner(
            AuthenticationService service
    ) {
        return args -> {
//            var admin = RegisterRequest.builder()
//                    .firstname("Admin")
//                    .lastname("Admin")
//                    .email("admin@mail.com")
//                    .password("password")
//                    .role(new Role(1))
//                    .build();
//            System.out.println("Admin token: " + service.register(admin, null).getAccessToken());
//
//            var manager = RegisterRequest.builder()
//                    .role(new Role(2))
//                    .firstname("User")
//                    .lastname("User")
//                    .email("user@mail.com")
//                    .password("password")
//                    .build();
//
//            System.out.println("User token: " + service.register(manager, null).getAccessToken());

        };
    }

}
