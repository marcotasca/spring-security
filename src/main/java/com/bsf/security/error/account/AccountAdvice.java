package com.bsf.security.error.account;

import com.bsf.security.exception._common.BTExceptionResponse;
import com.bsf.security.exception.account.DuplicateAccountException;
import lombok.RequiredArgsConstructor;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.util.Locale;

@RequiredArgsConstructor
@ControllerAdvice
public class AccountAdvice {

    private final MessageSource messageSource;

    @ResponseStatus(HttpStatus.CONFLICT)
    @ExceptionHandler({DuplicateAccountException.class})
    public ResponseEntity<BTExceptionResponse> handleDuplicateAccountException(DuplicateAccountException ex, Locale locale) {
        String errorMessage = messageSource.getMessage(ex.getMessage(), ex.getArgs(), locale);
        return new ResponseEntity<>(
                new BTExceptionResponse(errorMessage, HttpStatus.CONFLICT),
                HttpStatus.CONFLICT
        );
    }

}
