package com.smile.core.domain;


public class SysGroup extends Entity {
    /**
     * 代码
     */
    private String code;

    /**
     * 名称
     */
    private String name;


    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code == null ? null : code.trim();
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name == null ? null : name.trim();
    }


}