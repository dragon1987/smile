package com.smile.core.service;


import com.smile.core.dao.SysPermissionDao;
import com.smile.core.domain.SysPermission;
import com.smile.core.utils.UserHolder;
import com.smile.core.view.ZNode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Date;
import java.util.List;

@Service
public class SysPermissionService {

    private final static String TABLE = "sys_permission";

    @Autowired
    private SysPermissionDao sysPermissionDAO;


    public List<SysPermission> findByUserId(long userId) {
        return sysPermissionDAO.selectByUserId(userId);
    }


    public List<SysPermission> selectList() {
        return sysPermissionDAO.selectList();
    }

    public void add(SysPermission permission) {
        permission.setCreatedBy(UserHolder.getCurrentUserId());
        permission.setCreateTime(new Date());
        sysPermissionDAO.add(permission);
    }

    public void update(SysPermission permission) {
        permission.setUpdatedBy(UserHolder.getCurrentUserId());
        permission.setUpdateTime(new Date());
        sysPermissionDAO.update(permission);
    }

    public int removeByIds(Collection<Long> ids) {
        return sysPermissionDAO.removeByIds(ids);
    }

    public List<SysPermission> findByRoleId(Long roleId) {
        return sysPermissionDAO.selectByRoleId(roleId);
    }

    public static ZNode transfor(SysPermission permission) {
        ZNode zNode = new ZNode();
        zNode.setpId(permission.getpId());
        zNode.setOrder(permission.getLevelOrder());
        zNode.setId(permission.getId());
//        zNode.setUrl(permission.getMenuUrl());
        zNode.setName(permission.getName());
        return zNode;
    }

    public List<SysPermission> findByRoleCodes(List<String> roleCodes) {
        return sysPermissionDAO.selectByRoleCodes(roleCodes);
    }


    public List<SysPermission> findByRoleCode(String roleCode) {
        return sysPermissionDAO.selectByRoleCode(roleCode);
    }
}
