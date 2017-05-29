package com.smile.sharding.router;

import org.springframework.beans.factory.InitializingBean;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class DefaultSubtableRouterManager implements ISubtableRouterManager, InitializingBean {

    /*
     * 首先，系统有多个路由策略类，每个类要提供一个名字，用于匹配策略
     */
    private Map<String, ISubtableStrategy> routerMap = new HashMap<String, ISubtableStrategy>();

    private Set<ISubtableStrategy> routers = new HashSet<ISubtableStrategy>();

    public Set<ISubtableStrategy> getRouters() {
        return routers;
    }

    public void setRouters(Set<ISubtableStrategy> routers) {
        this.routers = routers;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        for (ISubtableStrategy router : this.getRouters()) {
            this.routerMap.put(router.getTable(), router);
        }
    }

    @Override
    public String getRouterResult(String table, Object value) {
        if (value == null) {
            return null;
        }
        ISubtableStrategy strategy = routerMap.get(table);
        if (strategy != null) {
            String result = strategy.getRouterResult(value);
            if (result == null) {
                throw new RuntimeException(value.getClass().getName() + " 请实现分表策略！");
            } else {
                return result;
            }
        }
        return table;
    }

}
