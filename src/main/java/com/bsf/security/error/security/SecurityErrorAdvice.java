package com.bsf.security.error.security;

import com.bsf.security.exception._common.BTException;
import com.bsf.security.exception._common.BTExceptionResolver;
import com.bsf.security.exception._common.BTExceptionResponse;
import com.bsf.security.exception.security.auth.AuthException;
import com.bsf.security.exception.security.auth.VerifyTokenRegistrationException;
import com.bsf.security.exception.security.jwt.InvalidJWTTokenException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import javax.naming.AuthenticationException;
import java.time.LocalDateTime;
import java.util.Locale;

@Slf4j
@RequiredArgsConstructor
@ControllerAdvice
public class SecurityErrorAdvice {

    @Autowired
    BTExceptionResolver btExceptionResolver;

    @ExceptionHandler({
            VerifyTokenRegistrationException.class, InvalidJWTTokenException.class
    })
    public ResponseEntity<Void> handleVerifyTokenRegistrationException(BTException ex, Locale locale) {
        log.info("[EXCEPTION] ({}) -> {}", BTException.class.getName(), LocalDateTime.now());
        return ResponseEntity.badRequest().build();
    }

    @ExceptionHandler({AuthException.class})
    public ResponseEntity<BTExceptionResponse> handleAuthenticationException(AuthException ex, Locale locale) {
        log.info("[EXCEPTION] ({}) -> {}", AuthenticationException.class.getName(), LocalDateTime.now());
        return btExceptionResolver.resolveAuthenticationBTException(ex, locale, HttpStatus.BAD_REQUEST);
    }


}
