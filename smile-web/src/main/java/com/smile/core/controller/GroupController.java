package com.smile.core.controller;

import com.smile.core.domain.SysGroup;
import com.smile.core.domain.SysRole;
import com.smile.core.service.SysGroupService;
import com.smile.core.service.SysRoleService;
import com.smile.sharding.page.Pagination;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.List;

/**
 * Created by zhutao on 2016/7/16.
 */
@Controller()
@RequestMapping("/group")
@RequiresRoles("admin")
public class GroupController {

    @Autowired
    private SysGroupService groupService;

    @RequestMapping("/index")
    public String index() {
        return "/group/index";
    }


    @RequestMapping("/find")
    @ResponseBody
    public Pagination<SysGroup> find(SysGroup group, Pagination<SysGroup> pagination) {
        groupService.selectList(group, pagination);
        return pagination;
    }

    @RequestMapping("/add/index")
    public String addIndex() {
        return "/group/add";
    }

    @RequestMapping("/add")
    @ResponseBody
    public void add(SysGroup group) {
        groupService.addGroup(group);
    }

    @RequestMapping("/edit/index")
    public String editIndex(long id, Model model) {
        SysGroup group = groupService.selectById(id);
        model.addAttribute("group", group);
        return "/group/edit";
    }

    @RequestMapping("/edit")
    @ResponseBody
    public void edit(SysGroup group) {
        groupService.updateGroup(group);
    }

    @RequestMapping("/del")
    @ResponseBody
    public void del(@RequestParam("ids") List<Long> ids) {
        groupService.deleteGroup(ids);
    }
}
