package com.smile.weather.domain;

import java.util.Date;

/**
 * Created by zhutao on 2017/4/19.
 */
public class DeviceRecord {

    /**
     * 记录id
      */
    private long id;

    /**
     * 设备id
     */
    private long deviceId;

    /**
     * 数据
     */
    private String data;


    /**
     * 风速
     */
    private Integer windSpeed;


    /**
     * 风向
     */
    private String windDirection;

    /**
     * 气压
     */
    private Integer barometer ;

    /**
     * 温度
     */
    private Integer temperature ;

    /**
     * pm2.5
     */
    private Integer pm25;

    /**
     * 通道
     */
    private String channel;

    /**
     * 噪声
     */
    private double noise;

    /**
     * 湿度
     */
    private double humidity ;

    /**
     * pm 10
     */
    private int pm10;

    /**
     * 上报时间
     */
    private Date reportDate;


    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public long getDeviceId() {
        return deviceId;
    }

    public void setDeviceId(long deviceId) {
        this.deviceId = deviceId;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public String getWindDirection() {
        return windDirection;
    }

    public void setWindDirection(String windDirection) {
        this.windDirection = windDirection;
    }

    public Integer getBarometer() {
        return barometer;
    }

    public void setBarometer(Integer barometer) {
        this.barometer = barometer;
    }

    public Integer getTemperature() {
        return temperature;
    }

    public void setTemperature(Integer temperature) {
        this.temperature = temperature;
    }

    public Integer getPm25() {
        return pm25;
    }

    public void setPm25(Integer pm25) {
        this.pm25 = pm25;
    }

    public String getChannel() {
        return channel;
    }

    public void setChannel(String channel) {
        this.channel = channel;
    }

    public double getNoise() {
        return noise;
    }

    public void setNoise(double noise) {
        this.noise = noise;
    }

    public double getHumidity() {
        return humidity;
    }

    public void setHumidity(double humidity) {
        this.humidity = humidity;
    }

    public int getPm10() {
        return pm10;
    }

    public void setPm10(int pm10) {
        this.pm10 = pm10;
    }

    public Date getReportDate() {
        return reportDate;
    }

    public void setReportDate(Date reportDate) {
        this.reportDate = reportDate;
    }


    public Integer getWindSpeed() {
        return windSpeed;
    }

    public void setWindSpeed(Integer windSpeed) {
        this.windSpeed = windSpeed;
    }
}
