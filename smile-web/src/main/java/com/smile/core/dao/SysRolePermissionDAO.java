package com.smile.core.dao;

import com.smile.core.domain.SysRolePermission;
import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

@Mapper
public interface SysRolePermissionDAO {

    @Delete("delete from sys_role_permission  where role_id=#{roleId}")
    int remove(@Param("roleId") long roleId);

    @Insert("<script> " +
            "insert into sys_role_permission " +
            "<trim prefix=\"(\" suffix=\")\" suffixOverrides=\",\"> " +
            "<if test=\"id != null   \"> " +
            "id," +
            "</if>" +
            "<if test=\"permissionId != null \">" +
            "permission_id," +
            "</if>" +
            "<if test=\"roleId != null \"> " +
            "role_id," +
            "</if>" +
            "<if test=\"createdBy != null  \">" +
            "created_by," +
            "</if>" +
            "<if test=\"createTime != null  \">" +
            "create_time," +
            "</if> " +
            "<if test=\"updatedBy != null \">" +
            "updated_by," +
            "</if>" +
            "<if test=\"updateTime != null  \">" +
            "update_time," +
            "</if>" +
            "</trim>" +
            "<trim prefix=\"values (\" suffix=\")\" suffixOverrides=\",\">" +
            "<if test=\"id != null  \">" +
            "#{id,jdbcType=BIGINT}," +
            "</if>" +
            "<if test=\"permissionId != null  \">" +
            "#{permissionId,jdbcType=BIGINT}," +
            "</if>" +
            "<if test=\"roleId != null  \">" +
            "#{roleId,jdbcType=BIGINT}," +
            "</if>" +
            "<if test=\"createdBy != null   \">" +
            "#{createdBy,jdbcType=BIGINT}," +
            "</if>" +
            "<if test=\"createTime != null   \">" +
            "#{createTime,jdbcType=TIMESTAMP}," +
            "</if>" +
            "<if test=\"updatedBy != null   \">" +
            "#{updatedBy,jdbcType=BIGINT}," +
            "</if>" +
            "<if test=\"updateTime != null   \">" +
            "#{updateTime,jdbcType=TIMESTAMP}," +
            "</if>" +
            "</trim>" +
            "</script> ")
    int insert(SysRolePermission entity);


}