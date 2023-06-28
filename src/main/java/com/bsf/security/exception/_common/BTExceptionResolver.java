package com.bsf.security.exception._common;

import com.bsf.security.exception.account.InvalidPasswordAccountException;
import com.bsf.security.exception.account.InvalidPasswordAccountListException;
import lombok.RequiredArgsConstructor;
import org.apache.coyote.Response;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

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

    public ResponseEntity<BTExceptionResponse> resolveAuthBTException(
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

    public ResponseEntity<List<BTExceptionResponse>> resolvePasswordValidationBTException(
            InvalidPasswordAccountListException ex, Locale locale, HttpStatus httpStatus
    ) {
        List<BTExceptionResponse> exceptionResponseList = new ArrayList<>();
        ex.getExceptions().forEach(btException -> {
            String errorMessage = validationMessageSource.getMessage(btException.getMessage(), btException.getArgs(), locale);
            exceptionResponseList.add(new BTExceptionResponse(errorMessage, httpStatus));
        });
        return new ResponseEntity<>(exceptionResponseList, httpStatus);
    }

}
