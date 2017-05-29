package com.smile.core.controller;

import com.alibaba.fastjson.JSON;
import com.smile.core.domain.SysPermission;
import com.smile.core.service.SysPermissionService;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * Created by zhutao on 2016/8/4.
 */
@Controller()
@RequestMapping("/menu")
public class MenuController {

    @Autowired
    private SysPermissionService permissionService;

    @RequestMapping("/index")
    @RequiresRoles("admin")
    public String index(Model model) {
        List<SysPermission> permissions = permissionService.selectList();
        processorSysPermission(permissions);
        model.addAttribute("zTree", JSON.toJSONString(permissions));
        return "/menu/index";
    }

    private void processorSysPermission(List<SysPermission> permissions) {
        Collections.sort(permissions, new Comparator<SysPermission>() {
            public int compare(SysPermission sysPermission1, SysPermission sysPermission2) {
                if (sysPermission1 == null || sysPermission1.getLevelOrder() == null) {
                    return 1;
                }
                if (sysPermission2 == null || sysPermission2.getLevelOrder() == null) {
                    return -1;
                }
                if (sysPermission1.getLevelOrder() > sysPermission2.getLevelOrder()) {
                    return 1;
                }
                if (sysPermission1.getLevelOrder() < sysPermission2.getLevelOrder()) {
                    return -1;
                }
                return 0;
            }
        });
    }

    @RequestMapping(value = "/edit", method = RequestMethod.POST)
    @ResponseBody
    @RequiresRoles("admin")
    public Long edit(SysPermission permission) {
        if (permission.getId() != null) {
            permissionService.update(permission);
        } else {
            permissionService.add(permission);
        }
        return permission.getId();
    }

    @RequestMapping("/delete")
    @ResponseBody
    @RequiresRoles("admin")
    public Integer delete(@RequestParam("ids") List<Long> ids) {
        return permissionService.removeByIds(ids);
    }
}
