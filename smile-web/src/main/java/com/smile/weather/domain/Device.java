package com.smile.weather.domain;

/**
 * Created by zhutao on 2017/4/19.
 */
public class Device {

    /**
     * 设备id
     */
    private long id;

    /**
     * 设备名称
     */
    private String name;

    /**
     * 设备所属的位置
     */
    private String location;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
    }
}
