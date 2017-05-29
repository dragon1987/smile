package com.smile.weather.service;

import com.smile.sharding.page.Pagination;
import com.smile.weather.dao.DeviceDao;
import com.smile.weather.dao.DeviceRecordDao;
import com.smile.weather.domain.Device;
import com.smile.weather.domain.DeviceRecord;
import org.apache.ibatis.annotations.Param;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Created by zhutao on 2017/4/23.
 */
@Service
public class DeviceService {

    @Autowired
    private DeviceDao deviceDao;

    @Autowired
    private DeviceRecordDao deviceRecordDao;


    public List<Device> findList(Pagination<Device> pagination) {
        return deviceDao.findAllDeviceByUserId(pagination);
    }

    public List<Device> findByPage(Long id, String name, Pagination<Device> pagination) {
        return deviceDao.findByPage(id, name, pagination);
    }

    public List<DeviceRecord> findRecordByDeviceId(Long deviceId, Pagination<DeviceRecord> pagination) {
        return deviceRecordDao.findDeviceRecordByDeviceId(deviceId, pagination);
    }


    public DeviceRecord findLastRecordByDeviceId(long deviceId) {
        return deviceRecordDao.findLastDeviceRecordByDeviceId(deviceId);
    }


}
