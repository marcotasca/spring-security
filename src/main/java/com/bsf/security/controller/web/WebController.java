package com.bsf.security.controller.web;

import com.bsf.security.sec.CurrentUser;
import com.bsf.security.sec.model.account.Account;
import com.bsf.security.sec.model.account.AccountRepository;
import com.bsf.security.sec.oauth.UserPrincipal;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class WebController {

    private final AccountRepository userRepository;

    @GetMapping("/profile")
    public Account getCurrentUser(Authentication authentication) {
        return userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));
    }

}
