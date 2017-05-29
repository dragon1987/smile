package com.smile.sharding.router;

import java.util.Set;

public interface ISubtableRouterManager {

    Set<ISubtableStrategy> getRouters();

    void setRouters(Set<ISubtableStrategy> routers);

    String getRouterResult(String table,Object value);
}
