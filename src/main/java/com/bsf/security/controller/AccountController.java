package com.bsf.security.controller;

import com.bsf.security.mapstruct.dtos.AccountDto;
import com.bsf.security.sec.account.Account;
import com.bsf.security.sec.account.AccountRepository;
import com.bsf.security.service.mapstruct.MapStruct;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Optional;

@RestController
@RequestMapping("/api/v1/account")
@RequiredArgsConstructor
public class AccountController {

    private final AccountRepository accountRepository;

    private final MapStruct mapStruct;

    private final PasswordEncoder passwordEncoder;

    @GetMapping
    public ResponseEntity<AccountDto> getAccountInfo(Authentication authentication) {
        Account account = accountRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new RuntimeException("Account not found"));
        return ResponseEntity.ok(mapStruct.accountToAccountDto(account));
    }

}
