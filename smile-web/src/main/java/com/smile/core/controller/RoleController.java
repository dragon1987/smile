package com.smile.core.controller;

import com.alibaba.fastjson.JSON;
import com.smile.core.domain.SysPermission;
import com.smile.core.domain.SysRole;
import com.smile.core.domain.SysRolePermission;
import com.smile.core.domain.SysUser;
import com.smile.core.service.SysPermissionService;
import com.smile.core.service.SysRoleService;
import com.smile.core.service.SysUserService;
import com.smile.core.view.ZNode;
import com.smile.sharding.page.Pagination;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by zhutao on 2016/7/16.
 */
@Controller()
@RequestMapping("/role")

public class RoleController {

    @Autowired
    private SysRoleService roleService;

    @Autowired
    private SysPermissionService permissionService;


    @RequestMapping("/index")
    @RequiresRoles("admin")
    public String index() {
        return "/role/index";
    }


    @RequestMapping("/find")
    @ResponseBody
    @RequiresRoles("admin")
    public Pagination<SysRole> find(SysRole user, Pagination<SysRole> pagination) {
        roleService.selectList(user, pagination);
        return pagination;
    }

    @RequestMapping("/add/index")
    @RequiresRoles("admin")
    public String addIndex() {
        return "/role/add";
    }

    @RequestMapping("/add")
    @ResponseBody
    @RequiresRoles("admin")
    public void add(SysRole role) {
        roleService.addRole(role);
    }

    @RequestMapping("/edit/index")
    @RequiresRoles("admin")
    public String editIndex(long id, Model model) {
        SysRole role = roleService.selectById(id);
        model.addAttribute("role", role);
        return "/role/edit";
    }

    @RequestMapping("/edit")
    @ResponseBody
    @RequiresRoles("admin")
    public void edit(SysRole role) {
        roleService.updateRole(role);
    }

    @RequestMapping("/del")
    @ResponseBody
    @RequiresRoles("admin")
    public void del(@RequestParam("ids") List<Long> ids) {
        roleService.deleteRole(ids);
    }


    @RequestMapping("/bind/index")
    @RequiresRoles("admin")
    public String bindIndex(long id, Model model) {
        SysRole role = roleService.selectById(id);
        model.addAttribute("role", role);

        List<SysPermission> allSysPermission = permissionService.selectList();
        List<ZNode> zNodes = new ArrayList<ZNode>();
        for (SysPermission sysPermission : allSysPermission) {
            zNodes.add(SysPermissionService.transfor(sysPermission));
        }
        List<SysPermission> sysPermissions = permissionService.findByRoleId(id);
        for (ZNode zNode : zNodes) {
            if (isCheck(sysPermissions, zNode)) {
                zNode.setChecked(true);
            }
        }
        model.addAttribute("roleId", id);
        model.addAttribute("zTree", JSON.toJSONString(zNodes));
        return "/role/bind";
    }


    private boolean isCheck(List<SysPermission> sysPermissions, ZNode zTree) {
        for (SysPermission sysPermission : sysPermissions) {
            if (sysPermission.getId().equals(zTree.getId())) {
                return true;
            }
        }
        return false;
    }

    @RequestMapping("/bind")
    @ResponseBody
    @RequiresRoles("admin")
    public void bind(@RequestParam("roleId") Long roleId, @RequestParam("menuIds") List<Long> menuIds) {
        roleService.removeRolePermission(roleId);
        List<SysRolePermission> rolePermissions = new ArrayList<SysRolePermission>();
        for (Long menuId : menuIds) {
            SysRolePermission rolePermission = new SysRolePermission();
            rolePermission.setPermissionId(menuId);
            rolePermission.setRoleId(roleId);
            rolePermissions.add(rolePermission);
        }
        roleService.addRolePermission(rolePermissions);
    }

}
