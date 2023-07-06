package com.bsf.security.service.auth.provider;

import com.bsf.security.sec.model.provider.XrefAccountProvider;
import com.bsf.security.sec.model.provider.XrefAccountProviderRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class ProviderServiceImpl implements ProviderService {

    @Autowired
    private XrefAccountProviderRepository xrefAccountProviderRepository;

    @Override
    public void addProviderToAccount(int providerId, int accountId) {
        var providerRelation = XrefAccountProvider
                .builder()
                .providerId(providerId)
                .accountId(accountId)
                .build();

        xrefAccountProviderRepository.save(providerRelation);
    }

}
