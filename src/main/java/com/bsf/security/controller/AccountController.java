package com.bsf.security.controller;

import com.bsf.security.exception._common.BTExceptionName;
import com.bsf.security.exception.account.AccountNotFoundException;
import com.bsf.security.mapstruct.dtos.AccountDto;
import com.bsf.security.sec.model.account.Account;
import com.bsf.security.sec.model.account.AccountRepository;
import com.bsf.security.service.mapstruct.AccountMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/me")
@RequiredArgsConstructor
public class AccountController {

    private final AccountRepository accountRepository;

    @Autowired
    AccountMapper accountMapper;

    @GetMapping
    public ResponseEntity<AccountDto> getAccountInfo(Authentication authentication) {
        Account account = accountRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new AccountNotFoundException(BTExceptionName.ACCOUNT_NOT_FOUND.name()));
        return ResponseEntity.ok(accountMapper.accountToAccountDto(account));
    }

}
