package com.bsf.security.service.account;

import com.bsf.security.sec.model.account.Account;

import java.util.Optional;

public interface AccountService {
    Optional<Account> findByEmail(String email);
    Account save(Account account);
}
