package com.bsf.security.error.security;

import com.bsf.security.exception._common.BTExceptionResolver;
import com.bsf.security.exception._common.BTExceptionResponse;
import com.bsf.security.exception.security.jwt.SecurityJWTException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.Locale;

@RequiredArgsConstructor
@ControllerAdvice
public class SecurityErrorAdvice {

    private final BTExceptionResolver btExceptionResolver;

    @ExceptionHandler({SecurityJWTException.class})
    public ResponseEntity<BTExceptionResponse> handleSecurityJWTException(SecurityJWTException ex, Locale locale) {
        return btExceptionResolver.resolveAuthBTException(ex, locale, HttpStatus.CONFLICT);
    }

}
