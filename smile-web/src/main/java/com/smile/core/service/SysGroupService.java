package com.smile.core.service;

import com.smile.core.dao.SysGroupDao;
import com.smile.core.domain.SysGroup;

import com.smile.core.utils.UserHolder;
import com.smile.sharding.page.Pagination;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;

/**
 * Created by zhutao on 2016/7/31.
 */
@Service
public class SysGroupService {

    @Autowired
    private SysGroupDao groupDao;



    public List<SysGroup> selectList(SysGroup group, Pagination<SysGroup> pagination) {
        return groupDao.selectList(group, pagination);
    }

    public void addGroup(SysGroup group) {
        group.setCreatedBy(UserHolder.getCurrentUserId());
        group.setCreateTime(new Date());
        groupDao.addGroup(group);
    }

    public SysGroup selectById(long roleId) {
        return groupDao.selectById(roleId);
    }

    public void updateGroup(SysGroup group) {
        group.setUpdatedBy(UserHolder.getCurrentUserId());
        group.setUpdateTime(new Date());
        groupDao.updateGroup(group);
    }


    public void deleteGroup(List<Long> ids) {
        groupDao.deleteGroup(ids);
    }

    public List<SysGroup> selectByUserId(Long userId, Pagination pagination) {
        return groupDao.selectByUserId(userId, pagination);
    }

    public List<SysGroup> selectUnbindGroupByUserId(Long userId, String name, Pagination pagination) {
        return groupDao.selectUnBindByUserId(userId, name, pagination);
    }





}
