package com.bsf.security.error.account;

import com.bsf.security.exception._common.BTExceptionResolver;
import com.bsf.security.exception._common.BTExceptionResponse;
import com.bsf.security.exception._common.BTExceptionResponseList;
import com.bsf.security.exception.account.AccountNotFoundException;
import com.bsf.security.exception.account.DuplicateAccountException;
import com.bsf.security.exception.account.InvalidPasswordAccountListException;
import com.bsf.security.exception.account.PasswordsDoNotMatchException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Locale;

@Slf4j
@RequiredArgsConstructor
@ControllerAdvice
public class AccountErrorAdvice {

    private final BTExceptionResolver btExceptionResolver;

    @ExceptionHandler({DuplicateAccountException.class})
    public ResponseEntity<BTExceptionResponse> handleDuplicateAccountException(DuplicateAccountException ex, Locale locale) {
        log.info("[EXCEPTION] ({}) -> {}", DuplicateAccountException.class.getName(), LocalDateTime.now());
        return btExceptionResolver.resolveBusinessBTException(ex, locale, HttpStatus.CONFLICT);
    }

    @ExceptionHandler({PasswordsDoNotMatchException.class})
    public ResponseEntity<BTExceptionResponse> handlePasswordDoNotMatchException(PasswordsDoNotMatchException ex, Locale locale) {
        log.info("[EXCEPTION] ({}) -> {}", PasswordsDoNotMatchException.class.getName(), LocalDateTime.now());
        return btExceptionResolver.resolveValidationBTException(ex, locale, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler({AccountNotFoundException.class})
    public ResponseEntity<BTExceptionResponse> handleAccountNotFoundException(AccountNotFoundException ex, Locale locale) {
        log.info("[EXCEPTION] ({}) -> {}", AccountNotFoundException.class.getName(), LocalDateTime.now());
        return btExceptionResolver.resolveValidationBTException(ex, locale, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler({InvalidPasswordAccountListException.class})
    public ResponseEntity<BTExceptionResponseList> handleInvalidPasswordAccountException(InvalidPasswordAccountListException ex, Locale locale) {
        log.info("[EXCEPTION] ({}) -> {}", InvalidPasswordAccountListException.class.getName(), LocalDateTime.now());
        return btExceptionResolver.resolvePasswordValidationBTException(ex, locale, HttpStatus.BAD_REQUEST);
    }

}
