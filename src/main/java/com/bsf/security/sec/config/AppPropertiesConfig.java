package com.bsf.security.sec.config;

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
}
