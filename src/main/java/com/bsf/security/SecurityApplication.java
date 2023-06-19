package com.bsf.security;

import com.bsf.security.auth.AuthenticationService;
import com.bsf.security.auth.RegisterRequest;
import com.bsf.security.user.Role;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

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
			var admin = RegisterRequest.builder()
					.firstname("Admin")
					.lastname("Admin")
					.email("admin@mail.com")
					.password("password")
					.role(Role.ADMIN)
					.build();
			System.out.println("Admin token: " + service.register(admin).getAccessToken());

			var manager = RegisterRequest.builder()
					.firstname("User")
					.lastname("User")
					.email("user@mail.com")
					.password("password")
					.role(Role.USER)
					.build();
			System.out.println("User token: " + service.register(manager).getAccessToken());

		};
	}

}
