package com.smile.sharding.utils;

import java.util.HashMap;
import java.util.Map;

public class CollectionGroup {

    private Map<String, Object> map = new HashMap<String, Object>();

    public void put(String key, Object value) {
        map.put(key, value);
    }

    public Object getGroup(String groupProperty) {
        return map.get("group." + groupProperty);
    }

    public Object getSum(String sumProperty) {
        return map.get("sum." + sumProperty);
    }

    public Double getAvg(String avgProperty) {
        return (Double) map.get("avg." + avgProperty);
    }

    public Integer getCount(String countProperty) {
        return (Integer) map.get("count." + countProperty);
    }
}
