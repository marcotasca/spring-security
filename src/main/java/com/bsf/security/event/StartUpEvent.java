package com.bsf.security.event;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.Locale;

@Slf4j
@Component
public class StartUpEvent {

    @EventListener(ApplicationReadyEvent.class)
    public void afterStartUpRun() {
        log.info("[EVENT] (Start Up) -> {}", LocalDateTime.now());

        // Imposto la lingua di default a US
        Locale.setDefault(Locale.US);
    }

}
