package com.bsf.security.exception._common;

import com.bsf.security.exception.account.InvalidPasswordAccountListException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

@Slf4j
@Service
@RequiredArgsConstructor
public class BTExceptionResolver {

    @Qualifier("businessMessageSource")
    private final MessageSource businessMessageSource;

    @Qualifier("validationMessageSource")
    private final MessageSource validationMessageSource;

    @Qualifier("authenticationMessageSource")
    private final MessageSource authenticationMessageSource;

    private ResponseEntity<BTExceptionResponse> resolveUnhandledBTException(String errorMessage, HttpStatus httpStatus) {
        // TODO: Scrivi a DB le eccezioni generate
        return new ResponseEntity<>(new BTExceptionResponse(errorMessage, httpStatus), httpStatus);
    }

    public void resolveAuthBTException(String type, Exception ex, String token) {
        log.error("\n[{}] -> {}\nToken: {}", type, ex.getMessage(), token);
    }

    public ResponseEntity<BTExceptionResponse> resolveAuthenticationBTException(
            BTException ex, Locale locale, HttpStatus httpStatus
    ) {
        String errorMessage = authenticationMessageSource.getMessage(ex.getMessage(), ex.getArgs(), locale);
        return new ResponseEntity<>(new BTExceptionResponse(errorMessage, httpStatus), httpStatus);
    }

    public ResponseEntity<BTExceptionResponse> resolveBusinessBTException(
            BTException ex, Locale locale, HttpStatus httpStatus
    ) {
        String errorMessage = businessMessageSource.getMessage(ex.getMessage(), ex.getArgs(), locale);
        return new ResponseEntity<>(new BTExceptionResponse(errorMessage, httpStatus), httpStatus);
    }

    public ResponseEntity<BTExceptionResponseList> resolvePasswordValidationBTException(
            InvalidPasswordAccountListException ex, Locale locale, HttpStatus httpStatus
    ) {
        List<String> messages = new ArrayList<>();
        ex.getExceptions().forEach(btException -> {
            String errorMessage = validationMessageSource.getMessage(btException.getMessage(), btException.getArgs(), locale);
            messages.add(errorMessage);
        });
        return new ResponseEntity<>(new BTExceptionResponseList(messages, httpStatus), httpStatus);
    }

    public ResponseEntity<BTExceptionResponse> resolveValidationBTException(
            BTException ex, Locale locale, HttpStatus httpStatus
    ) {
        String errorMessage = validationMessageSource.getMessage(ex.getMessage(), ex.getArgs(), locale);
        return new ResponseEntity<>(new BTExceptionResponse(errorMessage, httpStatus), httpStatus);
    }

}
