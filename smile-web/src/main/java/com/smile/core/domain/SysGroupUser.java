package com.smile.core.domain;


public class SysGroupUser extends Entity {
    /**
     * 用户组ID
     */
    private Long groupId;

    /**
     * 用户ID
     */
    private Long userId;


    public Long getGroupId() {
        return groupId;
    }

    public void setGroupId(Long groupId) {
        this.groupId = groupId;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }


}