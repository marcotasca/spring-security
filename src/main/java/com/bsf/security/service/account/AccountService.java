package com.bsf.security.service.account;

import com.bsf.security.sec.model.account.Account;

import java.util.Optional;

public interface AccountService {
    Optional<Account> findById(int accountId);
    Optional<Account> findByEmail(String email);
    Account save(Account account);
    void enableAccount(int accountId);
    void editPassword(String email, String currentPassword, String password, String confirmPassword);
    void editAccountName(String email, String firstName, String lastName);
}
