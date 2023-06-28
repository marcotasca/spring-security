package com.bsf.security;

import com.bsf.security.sec.account.Role;
import com.bsf.security.sec.auth.AuthenticationService;
import com.bsf.security.sec.auth.RegisterRequest;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.i18n.SessionLocaleResolver;

import java.util.Locale;

@SpringBootApplication
public class SecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityApplication.class, args);
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
