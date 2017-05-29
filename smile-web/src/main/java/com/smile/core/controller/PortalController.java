package com.smile.core.controller;

import com.smile.core.domain.SysPermission;
import com.smile.core.domain.SysUser;
import com.smile.core.service.SysPermissionService;
import com.smile.core.utils.UserHolder;
import com.smile.core.view.ZMenu;
import com.smile.core.view.ZNode;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.subject.support.WebDelegatingSubject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Controller
@RequiresRoles("admin")
public class PortalController {

    @Autowired
    private SysPermissionService permissionService;

    @RequestMapping("/")
    public String index(Model model) {
        SysUser user = UserHolder.getCurrentUser();
        Long userId = user.getId();
        model.addAttribute("zTree", initTree(userId));
        model.addAttribute("user", user);
        return "portal";
    }


    @RequestMapping("/index")
    public String index() {
        return "/index";
    }


    @RequestMapping("/welcome")
    public String welcome() {
        return "/index_v1";
    }

    @RequestMapping(value = "/login")
    public String login() {
        return "/login";
    }


    private ZMenu initTree(Long userId) {
        ZMenu menu = new ZMenu();
        List<SysPermission> permissions = permissionService.findByUserId(userId);
        Map<Long, ZNode> zNodeMap = new HashMap<Long, ZNode>();
        for (SysPermission permission : permissions) {
            if (!StringUtils.isEmpty(permission.getCode())
                    && permission.getMenuLevel() != null && (permission.getMenuLevel() == 1 || permission.getMenuLevel() == 2)
                    && permission.getIsHidden() != 1) {
                ZNode zNode = transforFromSysPermission(permission);
                if (permission.getpId() == 0) {
                    menu.addNodes(zNode);
                }
                zNodeMap.put(zNode.getId(), zNode);
            }
        }
        for (Map.Entry<Long, ZNode> zNodeEntry : zNodeMap.entrySet()) {
            ZNode zNode = zNodeEntry.getValue();
            ZNode pZNode = zNodeMap.get(zNode.getpId());
            if (pZNode != null) {
                pZNode.addSubZNodes(zNode);
            }
        }
        return menu;
    }

    private ZNode transforFromSysPermission(SysPermission permission) {
        ZNode zNode = new ZNode();
        zNode.setName(permission.getName());
        zNode.setUrl(permission.getMenuUrl());
        zNode.setOrder(permission.getLevelOrder());
        zNode.setId(permission.getId());
        zNode.setpId(permission.getpId());
        zNode.setMenuIcon(permission.getMenuIcon());
        return zNode;
    }

}
