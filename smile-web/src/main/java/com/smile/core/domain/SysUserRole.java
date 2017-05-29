package com.smile.core.domain;


public class SysUserRole extends Entity {
    /** 角色ID */
    private Long roleId;

    /** 用户ID */
    private Long userId;

    public Long getRoleId() {
        return roleId;
    }

    public void setRoleId(Long roleId) {
        this.roleId = roleId;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }
}