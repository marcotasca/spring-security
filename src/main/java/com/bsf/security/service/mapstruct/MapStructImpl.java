package com.bsf.security.service.mapstruct;

import com.bsf.security.mapstruct.dtos.AccountDto;
import com.bsf.security.sec.model.account.Account;
import org.springframework.stereotype.Component;

@Component
public class MapStructImpl implements MapStruct {

    @Override
    public AccountDto accountToAccountDto(Account account) {
        if (account == null) {
            return null;
        }

        AccountDto accountDto = new AccountDto();

        accountDto.setFirstName(account.getFirstname());
        accountDto.setLastName(account.getLastname());
        accountDto.setEmail(account.getEmail());
        accountDto.setStatus(account.getStatus().getName());

        return accountDto;
    }

}
