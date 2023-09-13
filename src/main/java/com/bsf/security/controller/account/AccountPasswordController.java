package com.bsf.security.controller.account;

import com.bsf.security.dao.request.account.RequestEditAccountPassword;
import com.bsf.security.service.account.AccountService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/me/password")
@RequiredArgsConstructor
public class AccountPasswordController {

    private final AccountService accountService;

    @PutMapping
    public ResponseEntity<Void> editAccountPassword(@RequestBody RequestEditAccountPassword request, Authentication authentication) {
        accountService.editPassword(authentication.getName(), request.password(), request.confirmPassword());
        return ResponseEntity.noContent().build();
    }

}
