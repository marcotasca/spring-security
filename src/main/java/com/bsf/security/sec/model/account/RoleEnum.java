package com.bsf.security.sec.model.account;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import java.util.Collections;
import java.util.Set;

@RequiredArgsConstructor
public enum RoleEnum {
    ADMIN(1,
            Set.of(
                    PermissionEnum.ADMIN_READ,
                    PermissionEnum.ADMIN_CREATE,
                    PermissionEnum.ADMIN_UPDATE,
                    PermissionEnum.ADMIN_DELETE
            )
    ),

    USER(2, Collections.emptySet());

    @Getter
    private final int roleId;

    @Getter
    private final Set<PermissionEnum> permissionEnums;

}
