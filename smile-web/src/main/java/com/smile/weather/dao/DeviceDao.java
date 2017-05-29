package com.smile.weather.dao;


import com.smile.sharding.page.Pagination;
import com.smile.weather.domain.Device;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.List;

/**
 * Created by zhutao on 2017/4/19.
 */
@Mapper
public interface DeviceDao {


    @Select("select * from device ")
    List<Device> findAllDeviceByUserId(@Param("page") Pagination<Device> pagination);


    @Select("<script>" +
            "select * from device " +
            " <where> " +
            "    <if test=\"id != null\">" +
            "         id = #{id}" +
            "    </if> " +
            "    <if test=\"name != null and name !=''\">" +
            "        AND name =  #{name} " +
            "    </if> " +
            "  </where>" +

            "</script>"
    )
    List<Device> findByPage(@Param("id") Long id, @Param("name") String name, @Param("page") Pagination<Device> pagination);

}
