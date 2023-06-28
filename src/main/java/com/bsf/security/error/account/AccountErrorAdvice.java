package com.bsf.security.error.account;

import com.bsf.security.exception._common.BTExceptionResolver;
import com.bsf.security.exception._common.BTExceptionResponse;
import com.bsf.security.exception.account.DuplicateAccountException;
import com.bsf.security.exception.account.InvalidPasswordAccountListException;
import lombok.RequiredArgsConstructor;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.util.List;
import java.util.Locale;

@RequiredArgsConstructor
@ControllerAdvice
public class AccountErrorAdvice {

    private final BTExceptionResolver btExceptionResolver;

    @ExceptionHandler({DuplicateAccountException.class})
    public ResponseEntity<BTExceptionResponse> handleDuplicateAccountException(DuplicateAccountException ex, Locale locale) {
        return btExceptionResolver.resolveBusinessBTException(ex, locale, HttpStatus.CONFLICT);
    }

    @ExceptionHandler({InvalidPasswordAccountListException.class})
    public ResponseEntity<List<BTExceptionResponse>> handleInvalidPasswordAccountException(InvalidPasswordAccountListException ex, Locale locale) {
        return btExceptionResolver.resolvePasswordValidationBTException(ex, locale, HttpStatus.BAD_REQUEST);
    }

}
