package com.bsf.security.controller.web;

import com.bsf.security.exception._common.BTExceptionName;
import com.bsf.security.exception.account.AccountNotFoundException;
import com.bsf.security.sec.model.account.Account;
import com.bsf.security.sec.model.account.AccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class WebController {

    private final AccountRepository userRepository;

    @GetMapping("/profile")
    public Account getCurrentUser(Authentication authentication) {
        return userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new AccountNotFoundException(BTExceptionName.ACCOUNT_NOT_FOUND.name()));
    }

}
