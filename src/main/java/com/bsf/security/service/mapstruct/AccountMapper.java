package com.bsf.security.service.mapstruct;

import com.bsf.security.mapstruct.dtos.AccountDto;
import com.bsf.security.sec.model.account.Account;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.factory.Mappers;

@Mapper(componentModel = "spring")
public interface AccountMapper {

    AccountMapper INSTANCE = Mappers.getMapper( AccountMapper.class );

    @Mapping(target = "status", source = "status.name")
    AccountDto accountToAccountDto(Account account);
}