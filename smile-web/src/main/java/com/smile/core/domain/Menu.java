package com.smile.core.domain;

/**
 * Created by zhutao on 2016/7/4.
 */
public class Menu extends Entity {

    /**
     * 图标
     */
    private String icon;
    /**
     * 名称
     */
    private String name;
    /**
     * url链接
     */
    private String url;
    /**
     * 父id
     */
    private int parentId;

    /**
     * 顺序
     */
    private int order;
    /**
     * 是否显示
     */
    private int isShow;


    public String getIcon() {
        return icon;
    }

    public void setIcon(String icon) {
        this.icon = icon;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public int getParentId() {
        return parentId;
    }

    public void setParentId(int parentId) {
        this.parentId = parentId;
    }

    public int getIsShow() {
        return isShow;
    }

    public void setIsShow(int isShow) {
        this.isShow = isShow;
    }

    public int getOrder() {
        return order;
    }

    public void setOrder(int order) {
        this.order = order;
    }
}
