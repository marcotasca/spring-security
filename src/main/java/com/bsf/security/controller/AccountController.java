package com.bsf.security.controller;

import com.bsf.security.mapstruct.dtos.AccountDto;
import com.bsf.security.sec.model.account.Account;
import com.bsf.security.sec.model.account.AccountRepository;
import com.bsf.security.service.mapstruct.MapStruct;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/account")
@RequiredArgsConstructor
public class AccountController {

    private final AccountRepository accountRepository;

    private final MapStruct mapStruct;

    @GetMapping
    public ResponseEntity<AccountDto> getAccountInfo(Authentication authentication) {
        if(authentication != null) System.out.println(20/0);
        Account account = accountRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new RuntimeException("Account not found"));
        return ResponseEntity.ok(mapStruct.accountToAccountDto(account));
    }

}
