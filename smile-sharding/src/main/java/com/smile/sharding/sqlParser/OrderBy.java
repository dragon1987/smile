package com.smile.sharding.sqlParser;

/**
 * Created by zhutao on 2014/11/21.
 */
public class OrderBy {
    private String name;

    private boolean asc;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public boolean isAsc() {
        return asc;
    }

    public void setAsc(boolean asc) {
        this.asc = asc;
    }
}
