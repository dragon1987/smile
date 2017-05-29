package com.smile.weather.dao;

import com.smile.sharding.page.Pagination;
import com.smile.weather.domain.DeviceRecord;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.List;

/**
 * Created by zhutao on 2017/4/19.
 */
@Mapper
public interface DeviceRecordDao {


    @Select("<script>" +
            "select * from device_record " +
            " <where> " +
            "    <if test=\"deviceId != null\">" +
            "         device_id = #{deviceId}" +
            "    </if> " +
            "  </where>" +
            " order by report_date desc" +
            "</script>"
    )
    List<DeviceRecord> findDeviceRecordByDeviceId(@Param("deviceId") Long deviceId, @Param("page") Pagination<DeviceRecord> pagination);


    @Select("select * from device_record where device_id =#{deviceId} order by report_date desc limit 1 ")
    DeviceRecord findLastDeviceRecordByDeviceId(@Param("deviceId") Long deviceId);




}
