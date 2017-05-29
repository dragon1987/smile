package com.smile.weather.controller;

import com.smile.sharding.page.Pagination;
import com.smile.weather.domain.Device;
import com.smile.weather.domain.DeviceRecord;
import com.smile.weather.domain.Result;
import com.smile.weather.dto.DeviceRecordDTO;
import com.smile.weather.service.DeviceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by zhutao on 2017/4/23.
 */
@Controller
@RequestMapping("/wavelab/record")
public class DeviceRecordController {

    @Autowired
    private DeviceService deviceService;


    @RequestMapping(value = "/getInfo", produces = "application/json")
    @ResponseBody
    public Result<DeviceRecordDTO> findDeviceRecord(Long deviceId) {
        Result<DeviceRecordDTO> result = new Result<DeviceRecordDTO>();
        result.setStatus(0);
        DeviceRecord deviceRecord = deviceService.findLastRecordByDeviceId(deviceId);
        if (deviceRecord != null) {
            result.setData(new DeviceRecordDTO(deviceRecord));
        }
        return result;
    }


    @RequestMapping(value = "/find", produces = "application/json")
    @ResponseBody
    public Pagination<DeviceRecordDTO> find(@RequestParam(value = "deviceId", required = false) Long deviceId, Pagination<DeviceRecord> pagination) {
        Pagination<DeviceRecordDTO> deviceRecordDTOPagination = new Pagination<DeviceRecordDTO>();
        deviceService.findRecordByDeviceId(deviceId, pagination);
        deviceRecordDTOPagination.setLimit(pagination.getLimit());
        deviceRecordDTOPagination.setOffset(pagination.getOffset());
        deviceRecordDTOPagination.setTotal(pagination.getTotal());
        List<DeviceRecordDTO> deviceRecordDTOS = new ArrayList<DeviceRecordDTO>();
        deviceRecordDTOPagination.setRows(deviceRecordDTOS);
        for (DeviceRecord deviceRecord : pagination.getRows()) {
            deviceRecordDTOS.add(new DeviceRecordDTO(deviceRecord));
        }
        return deviceRecordDTOPagination;
    }


    @RequestMapping(value = "/index")
    public String index() {
        return "record/index";
    }
}
