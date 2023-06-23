package com.bsf.security.sec.account;

import jakarta.persistence.*;
import lombok.*;

import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "role")
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private int id;

    @Column(name = "name")
    private String name;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "xref_role_permission",
            joinColumns = @JoinColumn(name = "fk_role_id"),
            inverseJoinColumns = @JoinColumn(name = "fk_permission_id")
    )
    private Set<Permission> permissions;

    public Role(int id) {
        this.id = id;
    }

}
