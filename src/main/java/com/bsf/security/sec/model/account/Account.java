package com.bsf.security.sec.model.account;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "account")
public class Account implements UserDetails, OAuth2User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Integer id;

    @ManyToOne
    @JoinColumn(name = "fk_role_id")
    private Role role;

    @ManyToOne
    @JoinColumn(name = "fk_account_status_id")
    private AccountStatus status;

    @JsonProperty("first_name")
    @Column(name = "first_name")
    private String firstname;

    @JsonProperty("last_name")
    @Column(name = "last_name")
    private String lastname;

    @Column(name = "email")
    private String email;

    @Column(name = "password")
    private String password;

    @Column(name = "provider")
    private String provider;

    @JsonProperty("created_at")
    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @JsonProperty("deleted_at")
    @Column(name = "deleted_at")
    private LocalDateTime deletedAt;

    @Transient
    private Map<String, Object> attributes;

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Mappo tutti i permessi del ruolo richiesto in SimpleGrantedAuthority
        var authorities = role.getPermissions()
                .stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getName()))
                .collect(Collectors.toList());

        // Aggiungo il ruolo richiamato
        authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getName()));

        return authorities;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        //return status.getName().equals(AccountStatusEnum.Enabled.name());
        return true;
    }

    @Override
    public String getName() {
        return String.valueOf(id);
    }
}
