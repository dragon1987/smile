package com.smile.core.domain;


public class SysRole extends Entity {
    /**
     * 角色名
     */
    private String name;

    /**
     * 角色编码
     */
    private String code;


    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name == null ? null : name.trim();
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code == null ? null : code.trim();
    }


}