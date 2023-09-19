package com.bsf.security.error.account;

import com.bsf.security.exception._common.BTExceptionResolver;
import com.bsf.security.exception._common.BTExceptionResponse;
import com.bsf.security.exception._common.BTExceptionResponseList;
import com.bsf.security.exception.account.*;
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
        return btExceptionResolver.resolveBusinessBTException(ex, locale, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler({InvalidEmailAccountException.class})
    public ResponseEntity<BTExceptionResponse> handleInvalidEmailAccountException(InvalidEmailAccountException ex, Locale locale) {
        log.info("[EXCEPTION] ({}) -> {}", InvalidEmailAccountException.class.getName(), LocalDateTime.now());
        return btExceptionResolver.resolveValidationBTException(ex, locale, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler({InvalidPasswordAccountListException.class})
    public ResponseEntity<BTExceptionResponseList> handleInvalidPasswordAccountException(InvalidPasswordAccountListException ex, Locale locale) {
        log.info("[EXCEPTION] ({}) -> {}", InvalidPasswordAccountListException.class.getName(), LocalDateTime.now());
        return btExceptionResolver.resolvePasswordValidationBTException(ex, locale, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler({FirstNameEmptyException.class})
    public ResponseEntity<BTExceptionResponse> handleFirstNameEmptyException(FirstNameEmptyException ex, Locale locale) {
        log.info("[EXCEPTION] ({}) -> {}", FirstNameEmptyException.class.getName(), LocalDateTime.now());
        return btExceptionResolver.resolveBusinessBTException(ex, locale, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler({LastNameEmptyException.class})
    public ResponseEntity<BTExceptionResponse> handleLastNameEmptyException(LastNameEmptyException ex, Locale locale) {
        log.info("[EXCEPTION] ({}) -> {}", LastNameEmptyException.class.getName(), LocalDateTime.now());
        return btExceptionResolver.resolveBusinessBTException(ex, locale, HttpStatus.BAD_REQUEST);
    }

}
