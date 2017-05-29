package com.smile.core.domain;


public class SysGroupRole extends Entity {
    /** 用户组ID */
    private Long groupId;

    /** 角色ID */
    private Long roleId;

    public Long getGroupId() {
        return groupId;
    }

    public void setGroupId(Long groupId) {
        this.groupId = groupId;
    }

    public Long getRoleId() {
        return roleId;
    }

    public void setRoleId(Long roleId) {
        this.roleId = roleId;
    }
}