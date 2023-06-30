package com.bsf.security.service.mapstruct;

import com.bsf.security.mapstruct.dtos.AccountDto;
import com.bsf.security.sec.model.account.Account;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface MapStruct {

    AccountDto accountToAccountDto(Account account);

}
