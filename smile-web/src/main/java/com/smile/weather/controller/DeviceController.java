package com.smile.weather.controller;

import com.smile.sharding.page.Pagination;
import com.smile.weather.domain.Device;
import com.smile.weather.domain.Result;
import com.smile.weather.service.DeviceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.List;

/**
 * Created by zhutao on 2017/4/23.
 */
@Controller
@RequestMapping("/wavelab/device")
public class DeviceController {


    @Autowired
    private DeviceService deviceService;

    @RequestMapping(value = "/getInfo", produces = "application/json")
    @ResponseBody
    public Result<List<Device>> findDeviceByPagination(@RequestParam(value = "userId", required = false) Long userId, Pagination<Device> pagination) {
        List<Device> devices = deviceService.findList(pagination);
        Result<List<Device>> result = new Result<List<Device>>();
        result.setStatus(0);
        result.setData(devices);
        return result;
    }

    @RequestMapping(value = "/find", produces = "application/json")
    @ResponseBody
    public Pagination<Device> find(@RequestParam(value = "id", required = false) Long id, @RequestParam(value = "name", required = false) String name, Pagination<Device> pagination) {
        deviceService.findByPage(id, name, pagination);
        return pagination;
    }


    @RequestMapping(value = "/index")
    public String index() {
        return "device/index";
    }


}
