package com.smile.core.domain;

public class SysRolePermission extends Entity {
    /** 权限ID */
    private Long permissionId;

    /** 角色ID */
    private Long roleId;

    public Long getPermissionId() {
        return permissionId;
    }

    public void setPermissionId(Long permissionId) {
        this.permissionId = permissionId;
    }

    public Long getRoleId() {
        return roleId;
    }

    public void setRoleId(Long roleId) {
        this.roleId = roleId;
    }
}