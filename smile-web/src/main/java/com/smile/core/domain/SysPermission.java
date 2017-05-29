package com.smile.core.domain;




public class SysPermission extends Entity {
    /**
     * 权限码（一般根据菜单的树形结果生成）
     */
    private String code;

    /**
     * 权限名称
     */
    private String name;

    /**
     * 层级
     */
    private Integer level;

    /**
     * 层级顺序
     */
    private Integer levelOrder;

    /**
     * 父节点ID
     */
    private Long pId;


    /**
     * 是否选中
     */
    private boolean checked;

    /**
     * 是否是菜单
     */
    private Integer menuLevel;

    /**
     * 菜单URL地址
     */
    private String menuUrl;

    /**
     * 图标
     */
    private String menuIcon;

    /**
     * 系统id
     */
    private String systemId;

    /**
     * 是否隐藏
     */
    private int isHidden;

    /**
     * 是否是公共的
     */
    private int isPublicFunction;

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

    public Integer getLevel() {
        return level;
    }

    public void setLevel(Integer level) {
        this.level = level;
    }

    public Integer getLevelOrder() {
        return levelOrder;
    }

    public void setLevelOrder(Integer levelOrder) {
        this.levelOrder = levelOrder;
    }


    public Integer getMenuLevel() {
        return menuLevel;
    }

    public void setMenuLevel(Integer menuLevel) {
        this.menuLevel = menuLevel;
    }

    public Long getpId() {
        return pId;
    }

    public void setpId(Long pId) {
        this.pId = pId;
    }

    public boolean isChecked() {
        return checked;
    }

    public void setChecked(boolean checked) {
        this.checked = checked;
    }

    public String getMenuUrl() {
        return menuUrl;
    }

    public void setMenuUrl(String menuUrl) {
        this.menuUrl = menuUrl == null ? null : menuUrl.trim();
    }

    public String getMenuIcon() {
        return menuIcon;
    }

    public void setMenuIcon(String menuIcon) {
        this.menuIcon = menuIcon;
    }

    public String getSystemId() {
        return systemId;
    }

    public void setSystemId(String systemId) {
        this.systemId = systemId;
    }

    public int getIsHidden() {
        return isHidden;
    }

    public void setIsHidden(int isHidden) {
        this.isHidden = isHidden;
    }

    public int getIsPublicFunction() {
        return isPublicFunction;
    }

    public void setIsPublicFunction(int isPublicFunction) {
        this.isPublicFunction = isPublicFunction;
    }
}