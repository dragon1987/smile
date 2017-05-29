package com.smile.core.view;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * Created by zhutao on 2015/3/17.
 * 菜单
 */
public class ZMenu {

    private List<ZNode> nodes=new ArrayList<ZNode>();

    public List<ZNode> getNodes() {
        return nodes;
    }

    public void addNodes(ZNode zNode) {
        this.nodes.add(zNode);
        Collections.sort(this.nodes, new Comparator<ZNode>() {
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
}
