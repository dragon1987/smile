package com.smile.core.service;

import com.smile.core.dao.SysRoleDao;
import com.smile.core.dao.SysRolePermissionDAO;
import com.smile.core.domain.SysRole;
import com.smile.core.domain.SysRolePermission;
import com.smile.core.domain.SysUser;
import com.smile.core.utils.UserHolder;
import com.smile.sharding.page.Pagination;
import org.apache.ibatis.annotations.Param;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;

/**
 * Created by zhutao on 2016/7/31.
 */
@Service
public class SysRoleService {

    @Autowired
    private SysRoleDao roleDao;

    @Autowired
    private SysRolePermissionDAO sysRolePermissionDAO;

    public List<SysRole> selectList(SysRole user, Pagination<SysRole> pagination) {
        return roleDao.selectList(user, pagination);
    }

    public void addRole(SysRole role) {
        role.setCreatedBy(UserHolder.getCurrentUserId());
        role.setCreateTime(new Date());
        roleDao.addRole(role);
    }

    public SysRole selectById(long roleId) {
        return roleDao.selectById(roleId);
    }

    public void updateRole(SysRole role) {
        role.setUpdatedBy(UserHolder.getCurrentUserId());
        role.setUpdateTime(new Date());
        roleDao.updateRole(role);
    }


    public void deleteRole(List<Long> ids) {
        roleDao.deleteRole(ids);
    }

    public int removeRolePermission(long roleId) {
        return sysRolePermissionDAO.remove(roleId);
    }

    @Transactional
    public int addRolePermission(List<SysRolePermission> rolePermissions) {
        int result = 0;
        for (SysRolePermission sysRolePermission : rolePermissions) {
//            sysRolePermission.setId(idGenerator.getLongID(ROLE_PERMISSION_TABLE));
            sysRolePermission.setCreatedBy(UserHolder.getCurrentUserId());
            sysRolePermission.setCreateTime(new Date());
            result += sysRolePermissionDAO.insert(sysRolePermission);
        }
        return result;
    }

    public List<SysRole> selectByUserId(Long userId, Pagination pagination) {
        return roleDao.selectByUserId(userId, pagination);
    }

    public List<SysRole> selectUnbindByUserId(Long userId,String roleName, Pagination pagination) {
        return roleDao.selectUnbindByUserId(userId, roleName, pagination);
    }

    public List<SysRole> findAllRolesByUserId(Long userId) {
        return roleDao.selectAllRolesByUserId(userId);
    }

}
