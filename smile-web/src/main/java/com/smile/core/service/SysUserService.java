package com.smile.core.service;

import com.smile.core.dao.SysGroupUserDAO;
import com.smile.core.dao.SysUserDao;
import com.smile.core.dao.SysUserRoleDAO;
import com.smile.core.domain.SysGroupUser;
import com.smile.core.domain.SysUser;
import com.smile.core.domain.SysUserRole;
import com.smile.core.utils.UserHolder;
import com.smile.sharding.page.Pagination;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;

/**
 * Created by zhutao on 2016/7/16.
 */
@Service
public class SysUserService {

    @Autowired
    private PasswordHelper passwordHelper;

    private final static String DEFAULT_PASSWORD = "123";

    @Autowired
    private SysUserDao userDao;

    @Autowired
    private SysUserRoleDAO userRoleDAO;

    @Autowired
    private SysGroupUserDAO groupUserDao;

    public List<SysUser> selectList(SysUser user, Pagination<SysUser> pagination) {
        return userDao.selectList(user, pagination);
    }

    public void addUser(SysUser user) {
        user.setPassword(DEFAULT_PASSWORD);
        passwordHelper.encryptPassword(user);
        user.setCreatedBy(UserHolder.getCurrentUserId());
        userDao.addUser(user);
    }

    public SysUser selectById(long userId) {
        return userDao.selectById(userId);
    }

    public void updateUser(SysUser user) {
        user.setUpdatedBy(UserHolder.getCurrentUserId());
        user.setUpdateTime(new Date());
        userDao.updateUser(user);
    }

    public void deleteUser(List<Long> userIds) {
        userDao.deleteUser(userIds);
    }

    @Transactional
    public int addUserRole(List<SysUserRole> userRoles) {
        int result = 0;
        for (SysUserRole sysUserRole : userRoles) {
//            sysUserRole.setId(idGenerator.getLongID(USER_ROLE_TABLE));
            sysUserRole.setCreatedBy(UserHolder.getCurrentUserId());
            sysUserRole.setCreateTime(new Date());
            result += userRoleDAO.insert(sysUserRole);
        }
        return result;
    }


    public int removeUserRoleByUserIdAndRoleIds(Long userId, List<Long> roleIds) {
        return userRoleDAO.removeByUserIdAndRoleIds(userId, roleIds);
    }

    public int addGroupUser(List<SysGroupUser> sysGroupUsers) {
        int result = 0;
        for (SysGroupUser sysGroupUser : sysGroupUsers) {
//            sysGroupUser.setId(idGenerator.getLongID(GROUP_USER_TABLE));
            sysGroupUser.setCreatedBy(UserHolder.getCurrentUserId());
            sysGroupUser.setCreateTime(new Date());
            result += groupUserDao.insert(sysGroupUser);
        }
        return result;
    }

    public int removeGroupUserByUserIdAndGroupIds(Long userId, List<Long> groupIds) {
        return groupUserDao.removeByUserIdAndGroupIds(userId, groupIds);
    }

    public SysUser selectByUserNameForPassword(String loginName) {
        return userDao.selectByUserNameForPassword(loginName);
    }


}
