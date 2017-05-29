package com.smile.core.view;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * Created by zhutao on 2015/3/17.
 */
public class ZNode {

    /**
     * 当前id
     */
    private long id;

    /**
     * 父Id
     */
    private long pId;

    /**
     * 菜单名称
     */
    private String name;

    /**
     * 菜单url
     */
    private String url;

    /**
     * 顺序
     */
    private int order;


    /**
     * 是否选中
     */
    private boolean checked;

    /**
     * 图标
     */
    private String menuIcon;


    /**
     * 编码
     */
    private String code;

    /**
     * 子菜单
     */
    private List<ZNode> subNodes = new ArrayList<ZNode>();


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

    public int getOrder() {
        return order;
    }

    public void setOrder(int order) {
        this.order = order;
    }

    public List<ZNode> getSubNodes() {
        return subNodes;
    }

    public List<ZNode> getChildren() {
        return subNodes;
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public long getpId() {
        return pId;
    }

    public void setpId(long pId) {
        this.pId = pId;
    }

    public void addSubZNodes(ZNode zNode) {
        this.subNodes.add(zNode);
        Collections.sort(this.subNodes, new Comparator<ZNode>() {
            @Override
            public int compare(ZNode zNode1, ZNode zNode2) {
                if (zNode1 == null) {
                    return -1;
                }
                if (zNode2 == null) {
                    return 1;
                }
                return zNode1.getOrder() > zNode2.getOrder() ? 1 : -1;
            }
        });
    }


    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public boolean isChecked() {
        return checked;
    }

    public void setChecked(boolean checked) {
        this.checked = checked;
    }

    public String getMenuIcon() {
        return menuIcon;
    }

    public void setMenuIcon(String menuIcon) {
        this.menuIcon = menuIcon;
    }
}
