package com.bsf.security.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;

import java.util.ArrayList;
import java.util.List;

@Data
@EnableAsync
@Configuration
@ConfigurationProperties(prefix = "application")
public class AppPropertiesConfig {

    private List<String> authorizedRedirectUris = new ArrayList<>();

    private Security security = new Security();

    @Data
    public static class Security {
        private Jwt jwt = new Jwt();

        @Data
        public static class Jwt {
            private String secretKey;
            private int expiration;
            private RefreshToken refreshToken = new RefreshToken();
            private RegistrationToken registrationToken = new RegistrationToken();

            @Data
            public static class RefreshToken {
                private int expiration;
            }

            @Data
            public static class RegistrationToken {
                private int expiration;
            }

        }

    }
}
