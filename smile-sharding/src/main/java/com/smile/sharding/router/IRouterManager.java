package com.smile.sharding.router;

import java.util.Set;

public interface IRouterManager {

	Set<IRouterStrategy> getRouters();

	void setRouters(Set<IRouterStrategy> routers);

	String getRouterResult(String statement, Object value);
}
