package com.bsf.security.sec.model.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Integer> {

    @Query(value = """
        select t\s
        from Token t\s
        inner join Account a on t.account.id = a.id\s
        where a.id = :id\s
    """)
    List<Token> findAllValidTokenByUser(Integer id);

    List<Token> findAllByAccountId(Integer id);

    Optional<Token> findByAccessToken(String accessToken);
    Optional<Token> findByAccountIdAndTokenScopeCategoryId(int accountId, int tokenScopeCategoryId);

}
