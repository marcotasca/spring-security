package com.bsf.security.sec.account;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import java.util.Collections;
import java.util.Set;

@RequiredArgsConstructor
public enum RoleEnum {
    USER(1, Collections.emptySet()),
    ADMIN(2,
            Set.of(
                    PermissionEnum.ADMIN_READ,
                    PermissionEnum.ADMIN_CREATE,
                    PermissionEnum.ADMIN_UPDATE,
                    PermissionEnum.ADMIN_DELETE
            )
    );

    @Getter
    private final int roleId;

    @Getter
    private final Set<PermissionEnum> permissionEnums;

}
