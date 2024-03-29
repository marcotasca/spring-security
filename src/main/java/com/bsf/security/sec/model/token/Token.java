package com.bsf.security.sec.model.token;

import com.bsf.security.sec.model.account.Account;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "token")
public class Token {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    @ManyToOne
    @JoinColumn(name = "fk_account_id")
    private Account account;

    @ManyToOne
    @JoinColumn(name = "fk_token_type_id")
    private TokenType tokenType;

    @ManyToOne
    @JoinColumn(name = "fk_token_scope_category_id")
    private TokenScopeCategory tokenScopeCategory;

    @Lob
    @Column(name = "access_token")
    private String accessToken;

    @Column(name = "access_token_expiration")
    private Date accessTokenExpiration;

    @Lob
    @Column(name = "refresh_token")
    private String refreshToken;

    @Column(name = "refresh_token_expiration")
    private Date refreshTokenExpiration;

    @Column(name = "ip_address")
    private String ipAddress;

    public boolean isAccessTokenExpired() {
        return getAccessTokenExpiration().toInstant().isBefore(LocalDateTime.now().toInstant(ZoneOffset.UTC));
    }

    public boolean isRefreshTokenExpired() {
        return getRefreshTokenExpiration().toInstant().isBefore(LocalDateTime.now().toInstant(ZoneOffset.UTC));
    }

}
