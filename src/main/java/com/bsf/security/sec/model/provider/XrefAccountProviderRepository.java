package com.bsf.security.sec.model.provider;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface XrefAccountProviderRepository extends JpaRepository<XrefAccountProvider, Integer> {
}
