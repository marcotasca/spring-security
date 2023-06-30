package com.bsf.security.sec.demo;

import com.bsf.security.sec.model.account.Account;
import com.bsf.security.sec.model.token.Token;
import com.bsf.security.sec.model.token.TokenRepository;
import com.bsf.security.sec.model.account.Permission;
import com.bsf.security.sec.model.account.AccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;
import java.util.Set;

@RestController
@RequestMapping("/api/v1/demo")
@RequiredArgsConstructor
public class DemoController {


    private final AccountRepository accountRepository;

    private final TokenRepository tokenRepository;

    @GetMapping
    public ResponseEntity<String> sayHello() {
        return ResponseEntity.ok("Hello from secured endpoint.");
    }

    @GetMapping(value = "/abc")
    public ResponseEntity<Set<Permission>> getPermission() {
        Optional<Token> token = tokenRepository.findById(1);
        System.out.println(token);
        Optional<Account> account = accountRepository.findById(1);
        System.out.println(account.get().getRole());
        return account.map(value -> ResponseEntity.ok(value.getRole().getPermissions())).orElse(null);
    }

}
