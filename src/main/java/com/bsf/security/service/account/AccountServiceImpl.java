package com.bsf.security.service.account;

import com.bsf.security.exception._common.BTExceptionName;
import com.bsf.security.exception.account.*;
import com.bsf.security.sec.model.account.Account;
import com.bsf.security.sec.model.account.AccountRepository;
import com.bsf.security.sec.model.account.AccountStatus;
import com.bsf.security.sec.model.account.AccountStatusEnum;
import com.bsf.security.service.auth.token.TokenService;
import com.bsf.security.validation.password.PasswordConstraintValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AccountServiceImpl implements AccountService {

    @Autowired
    private AccountRepository accountRepository;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public Optional<Account> findById(int accountId) {
        return accountRepository.findById(accountId);
    }

    @Override
    public Optional<Account> findByEmail(String email) {
        return accountRepository.findByEmail(email);
    }

    @Override
    public Account save(Account account) {
        return accountRepository.save(account);
    }

    @Override
    public void enableAccount(int accountId) {
        findById(accountId).ifPresent(account -> {
            account.setStatus(new AccountStatus(AccountStatusEnum.Enabled.getStatusId()));
            save(account);
            tokenService.revokeAllAccountTokens(account);
        });
    }

    @Override
    public void editPassword(String email, String currentPassword, String password, String confirmPassword) {
        Account account = findByEmail(email)
                .orElseThrow(() -> new AccountNotFoundException(BTExceptionName.ACCOUNT_NOT_FOUND.name()));

        // Controllo che l'email corrente sia giusta
        if(!passwordEncoder.matches(currentPassword, account.getPassword()))
            throw new PasswordsDoNotMatchException(BTExceptionName.CURRENT_PASSWORD_DO_NOT_MATCH.name());

        // Controllo che la password soddisfi i requisiti minimi
        PasswordConstraintValidator.isValid(password);
        if (!password.equals(confirmPassword))
            throw new PasswordsDoNotMatchException(BTExceptionName.AUTH_REGISTRATION_PASSWORDS_DO_NOT_MATCH.name());

        account.setPassword(passwordEncoder.encode(password));
        save(account);
    }

    @Override
    public void editAccountName(String email, String firstName, String lastName) {
        // Controllo che il nome non sia vuoto
        if(firstName == null || firstName.isEmpty())
            throw new FirstNameEmptyException(BTExceptionName.FIRST_NAME_CAN_NOT_BE_EMPTY.name());

        // Controllo che il cognome non sia vuoto
        if(lastName == null || lastName.isEmpty())
            throw new LastNameEmptyException(BTExceptionName.LAST_NAME_CAN_NOT_BE_EMPTY.name());

        findByEmail(email).ifPresent(account -> {
            account.setFirstname(firstName);
            account.setLastname(lastName);
            save(account);
        });
    }
}
