package com.bsf.security.error.security;

import com.bsf.security.exception._common.BTExceptionResolver;
import com.bsf.security.exception._common.BTExceptionResponse;
import com.bsf.security.exception.account.DuplicateAccountException;
import com.bsf.security.exception.security.auth.VerifyTokenRegistrationException;
import com.bsf.security.exception.security.jwt.InvalidJWTTokenException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.time.LocalDateTime;
import java.util.Locale;

@Slf4j
@RequiredArgsConstructor
@ControllerAdvice
public class SecurityErrorAdvice {

    @ExceptionHandler({
            VerifyTokenRegistrationException.class, InvalidJWTTokenException.class
    })
    public ResponseEntity<Void> handleVerifyTokenRegistrationException(VerifyTokenRegistrationException ex, Locale locale) {
        log.info("[EXCEPTION] ({}) -> {}", VerifyTokenRegistrationException.class.getName(), LocalDateTime.now());
        return ResponseEntity.badRequest().build();
    }


}
