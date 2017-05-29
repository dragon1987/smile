package com.smile.sharding.router;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.InitializingBean;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class DefaultRouterManager implements IRouterManager, InitializingBean {

    /*
     * 首先，系统有多个路由策略类，每个类要提供一个名字，用于匹配策略
     */
    private Map<String, IRouterStrategy> routerMap = new HashMap<String, IRouterStrategy>();

    private Map<String, String> rules = new HashMap<String, String>();

    private Set<IRouterStrategy> routers = new HashSet<IRouterStrategy>();

    public Set<IRouterStrategy> getRouters() {
        return routers;
    }

    public void setRouters(Set<IRouterStrategy> routers) {
        this.routers = routers;
    }

    public void setRules(Map<String, String> rules) {
        this.rules = rules;
    }

    public Map<String, String> getRules() {
        return rules;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        for (IRouterStrategy router : this.getRouters()) {
            this.routerMap.put(router.getRouterKey(), router);
        }
    }

    public String getRouterResult(String statement, Object value) {
        if (statement == null) {
            throw new RuntimeException("statement can't null!");
        }
        // qing,优先走指定的路由
        if (rules.containsKey(statement)) {
            return rules.get(statement);
        }
        String nameSpace = null;
        int index = statement.lastIndexOf(".");
        if (index > 0) {// 有命名空间
            nameSpace = statement.substring(0, index);
            if (StringUtils.isNotEmpty(nameSpace) && rules.containsKey(nameSpace)) {
                return rules.get(nameSpace);
            }
        }

        String result = null;
        // 1.根据state的全名找路由
        IRouterStrategy strategy = routerMap.get(statement);

        // 2.根据statement的命名空间找路由
        if (strategy == null) {
            if (StringUtils.isNotEmpty(nameSpace)) {
                for (Map.Entry<String, IRouterStrategy> entry : routerMap.entrySet()) {
                    if (statement.substring(0, index).startsWith(entry.getKey())) {
                        strategy = entry.getValue();
                        break;
                    }
                }
            }
        }

        // 3.根据value的类型全名找路由策略类
        if (strategy == null) {
            if (value != null) {
                strategy = routerMap.get(value.getClass().getName());
            }
        }

        // 4.根据value的包名找路由
        if (strategy == null) {
            if (value != null) {
                String packageName = value.getClass().getPackage().getName();
                strategy = routerMap.get(packageName);
            }
        }

        if (strategy != null) {
            result = strategy.getRouterResult(value);
            if (result == null) {
                throw new RuntimeException(statement + " 请实现路由策略！");
            }
        }
        return result;// 没有找到会返回null，look中会处理
    }
}
