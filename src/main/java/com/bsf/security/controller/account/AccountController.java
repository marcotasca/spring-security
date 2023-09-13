package com.bsf.security.controller.account;

import com.bsf.security.dao.request.account.RequestEditAccountName;
import com.bsf.security.exception._common.BTExceptionName;
import com.bsf.security.exception.account.AccountNotFoundException;
import com.bsf.security.dao.mapstruct.dto.AccountDto;
import com.bsf.security.sec.model.account.Account;
import com.bsf.security.service.account.AccountService;
import com.bsf.security.service.mapstruct.AccountMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/me")
@RequiredArgsConstructor
public class AccountController {

    private final AccountService accountService;

    @Autowired
    AccountMapper accountMapper;

    @GetMapping
    public ResponseEntity<AccountDto> getAccountInfo(Authentication authentication) {
        Account account = accountService.findByEmail(authentication.getName())
                .orElseThrow(() -> new AccountNotFoundException(BTExceptionName.ACCOUNT_NOT_FOUND.name()));
        return ResponseEntity.ok(accountMapper.accountToAccountDto(account));
    }

    @PutMapping
    public ResponseEntity<AccountDto> editAccountInfo(
            @RequestBody RequestEditAccountName request,
            Authentication authentication
    ) {
        accountService.editAccountName(authentication.getName(), request.firstName(), request.lastName());
        return ResponseEntity.noContent().build();
    }

}
