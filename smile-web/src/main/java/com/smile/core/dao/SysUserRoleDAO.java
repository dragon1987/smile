package com.smile.core.dao;


import com.smile.core.domain.SysUserRole;
import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

@Mapper
public interface SysUserRoleDAO {

    /**
     * 插入用户和角色对应
     *
     * @param entity
     * @return
     */
    @Insert("<script>" +
            "insert into sys_user_role " +
            "<trim prefix=\"(\" suffix=\")\" suffixOverrides=\",\"> " +
            " <if test=\"id != null \"> " +
            "    id, " +
            "</if> " +
            "<if test=\"roleId != null  \"> " +
            "   role_id, " +
            "</if> " +
            "<if test=\"userId != null \"> " +
            "   user_id, " +
            "</if> " +
            "<if test=\"createdBy != null  \"> " +
            "    created_by, " +
            " </if> " +
            "<if test=\"createTime != null \"> " +
            "  create_time, " +
            "</if>" +
            "<if test=\"updatedBy != null  \">\n" +
            "   updated_by, " +
            "</if> " +
            "<if test=\"updateTime != null  \"> " +
            "   update_time, " +
            "</if> " +
            "</trim> " +
            "<trim prefix=\"values (\" suffix=\")\" suffixOverrides=\",\"> " +
            "<if test=\"id != null  \"> " +
            "  #{id,jdbcType=BIGINT}," +
            "</if>" +
            "<if test=\"roleId != null  \"> " +
            "  #{roleId,jdbcType=BIGINT}," +
            "</if>" +
            "<if test=\"userId != null \"> " +
            "#{userId,jdbcType=BIGINT}, " +
            "</if>" +
            "<if test=\"createdBy != null  \"> " +
            "  #{createdBy,jdbcType=BIGINT}, " +
            "</if>" +
            "<if test=\"createTime != null \"> " +
            "  #{createTime,jdbcType=TIMESTAMP}, " +
            "</if>" +
            "<if test=\"updatedBy != null  \">" +
            "   #{updatedBy,jdbcType=BIGINT}," +
            "</if>" +
            "<if test=\"updateTime != null \">" +
            "  #{updateTime,jdbcType=TIMESTAMP}," +
            "</if>" +
            "</trim>" +
            "</script>")
    int insert(SysUserRole entity);

    /**
     * 批量删除用户和角色对应
     *
     * @param userId
     * @param roleIds
     * @return
     */
    @Delete("<script>delete from sys_user_role " +
            "where user_id = #{userId,jdbcType=BIGINT} and role_id in " +
            "<foreach item=\"item\" collection=\"roleIds\" open=\"(\" separator=\",\" close=\")\"> " +
            "   #{item} " +
            "</foreach>" +
            "</script>")
    Integer removeByUserIdAndRoleIds(@Param("userId") Long userId, @Param("roleIds") List<Long> roleIds);

}
