package com.smile.core.controller;

import com.alibaba.fastjson.JSON;
import com.smile.core.domain.*;
import com.smile.core.service.SysGroupService;
import com.smile.core.service.SysPermissionService;
import com.smile.core.service.SysRoleService;
import com.smile.core.service.SysUserService;
import com.smile.core.view.ZNode;
import com.smile.sharding.page.Pagination;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.util.CollectionUtils;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by zhutao on 2016/7/16.
 */
@Controller()
@RequestMapping("/user")
public class UserController {

    @Autowired
    private SysUserService userService;

    @Autowired
    private SysRoleService roleService;

    @Autowired
    private SysGroupService groupService;

    @RequestMapping("/index")
    @RequiresRoles("admin")
    public String index() {
        return "/user/index";
    }


    @RequestMapping("/find")
    @ResponseBody
    @RequiresRoles("admin")
    public Pagination<SysUser> find(SysUser user, Pagination<SysUser> pagination) {
        userService.selectList(user, pagination);
        return pagination;
    }

    @RequestMapping("/add/index")
    @RequiresRoles("admin")
    public String addIndex() {
        return "/user/add";
    }

    @RequestMapping("/add")
    @ResponseBody
    @RequiresRoles("admin")
    public long add(SysUser user) {
        if (user.getId() == null) {
            userService.addUser(user);
        } else {
            userService.updateUser(user);
        }
        return user.getId();
    }

    @RequestMapping("/edit/index")
    @RequiresRoles("admin")
    public String editIndex(long id, Model model) {
        SysUser user = userService.selectById(id);
        model.addAttribute("user", user);
        return "/user/edit";
    }

    @RequestMapping("/edit")
    @ResponseBody
    @RequiresRoles("admin")
    public void edit(SysUser user) {
        userService.updateUser(user);
    }

    @RequestMapping("/del")
    @ResponseBody
    @RequiresRoles("admin")
    public void del(@RequestParam("ids") List<Long> ids) {
        userService.deleteUser(ids);
    }

    @RequestMapping("/role/find/{userId}")
    @ResponseBody
    @RequiresRoles("admin")
    public Pagination<SysRole> findRole(@PathVariable("userId") long userId, Pagination<SysRole> pagination) {
        roleService.selectByUserId(userId, pagination);
        return pagination;
    }

    @RequestMapping("/role/toBind/{id}")
    @RequiresRoles("admin")
    public String toBindRole(@PathVariable("id") Long userId, Model model) {
        model.addAttribute("userId", userId);
        return "/user/bindRole";
    }

    @RequestMapping("/role/findUnbind/{id}")
    @ResponseBody
    @RequiresRoles("admin")
    public Pagination<SysRole> findUnbindRoleByUserId(@PathVariable("id") Long userId, @RequestParam(value = "name", required = false) String name, Pagination pagination) {
        roleService.selectUnbindByUserId(userId, name, pagination);
        return pagination;
    }

    @RequestMapping("/bind/role")
    @ResponseBody
    @RequiresRoles("admin")
    public int bindRole(@RequestParam("userId") Long userId, @RequestParam("roleIds") List<Long> roleIds) {
        List<SysUserRole> sysUserRoleDTOs = new ArrayList<SysUserRole>();
        for (Long roleId : roleIds) {
            SysUserRole sysUserRoleDTO = new SysUserRole();
            sysUserRoleDTO.setUserId(userId);
            sysUserRoleDTO.setRoleId(roleId.longValue());
            sysUserRoleDTOs.add(sysUserRoleDTO);
        }
        if (!CollectionUtils.isEmpty(sysUserRoleDTOs)) {
            return userService.addUserRole(sysUserRoleDTOs);
        } else {
            return 0;
        }
    }

    @RequestMapping(value = "/role/remove/{userId}", method = RequestMethod.POST)
    @ResponseBody
    @RequiresRoles("admin")
    public void unbindRole(@PathVariable("userId") Long userId, @RequestParam("ids") List<Long> ids) {
        if (!CollectionUtils.isEmpty(ids)) {
            userService.removeUserRoleByUserIdAndRoleIds(userId, ids);
        }
    }


    @RequestMapping("/group/toBind/{id}")
    @RequiresRoles("admin")
    public String toBindGroup(@PathVariable("id") Long userId, Model model) {
        model.addAttribute("userId", userId);
        return "/user/bindGroup";
    }


    @RequestMapping("/group/find/{userId}")
    @ResponseBody
    @RequiresRoles("admin")
    public Pagination<SysGroup> findGorup(@PathVariable("userId") long userId, Pagination<SysGroup> pagination) {
        groupService.selectByUserId(userId, pagination);
        return pagination;
    }

    @RequestMapping("/group/findUnbind/{id}")
    @ResponseBody
    @RequiresRoles("admin")
    public Pagination<SysGroup> findUnbindGroupByUserId(@PathVariable("id") Long userId, @RequestParam(value = "name", required = false) String name, Pagination pagination) {
        groupService.selectUnbindGroupByUserId(userId, name, pagination);
        return pagination;
    }


    @RequestMapping("/bind/group")
    @ResponseBody
    @RequiresRoles("admin")
    public int bindGroup(@RequestParam("userId") Long userId, @RequestParam("groupIds") List<Long> groupIds) {
        List<SysGroupUser> sysGroupUsers = new ArrayList<SysGroupUser>();
        for (Long groupId : groupIds) {
            SysGroupUser groupUser = new SysGroupUser();
            groupUser.setUserId(userId);
            groupUser.setGroupId(groupId.longValue());
            sysGroupUsers.add(groupUser);
        }
        if (!CollectionUtils.isEmpty(sysGroupUsers)) {
            return userService.addGroupUser(sysGroupUsers);
        } else {
            return 0;
        }
    }

    @RequestMapping(value = "/group/remove/{userId}", method = RequestMethod.POST)
    @ResponseBody
    @RequiresRoles("admin")
    public void unbindGroup(@PathVariable("userId") Long userId, @RequestParam("ids") List<Long> ids) {
        if (!CollectionUtils.isEmpty(ids)) {
            userService.removeGroupUserByUserIdAndGroupIds(userId, ids);
        }
    }

}
