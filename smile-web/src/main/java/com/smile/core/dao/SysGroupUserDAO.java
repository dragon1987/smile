package com.smile.core.dao;


import com.smile.core.domain.SysGroupUser;
import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;


@Mapper
public interface SysGroupUserDAO {

    /**
     * 插入用户和用户组对应
     *
     * @param groupUser
     * @return
     */
    @Insert("<script>insert into sys_group_user " +
            "<trim prefix=\"(\" suffix=\")\" suffixOverrides=\",\"> " +
            "    <if test=\"id != null \"> " +
            "        id, " +
            "    </if> " +
            "    <if test=\"groupId != null  \"> " +
            "        group_id, " +
            "    </if> " +
            "    <if test=\"userId != null \"> " +
            "        user_id, " +
            "    </if> " +
            "    <if test=\"createdBy != null  \"> " +
            "        created_by, " +
            "    </if> " +
            "    <if test=\"createTime != null \"> " +
            "        create_time, " +
            "    </if> " +
            "    <if test=\"updatedBy != null  \"> " +
            "        updated_by, " +
            "    </if> " +
            "    <if test=\"updateTime != null \"> " +
            "        update_time, " +
            "    </if> " +
            "    <if test=\"isDeleted != null  \"> " +
            "        is_deleted, " +
            "    </if> " +
            "</trim> " +
            "<trim prefix=\"values (\" suffix=\")\" suffixOverrides=\",\"> " +
            "    <if test=\"id != null  \"> " +
            "        #{id,jdbcType=BIGINT}, " +
            "    </if> " +
            "    <if test=\"groupId != null  \"> " +
            "        #{groupId,jdbcType=BIGINT}, " +
            "    </if> " +
            "    <if test=\"userId != null  \"> " +
            "        #{userId,jdbcType=BIGINT}, " +
            "    </if> " +
            "    <if test=\"createdBy != null  \"> " +
            "        #{createdBy,jdbcType=BIGINT}, " +
            "    </if> " +
            "    <if test=\"createTime != null  \"> " +
            "        #{createTime,jdbcType=TIMESTAMP}, " +
            "    </if> " +
            "    <if test=\"updatedBy != null  \"> " +
            "        #{updatedBy,jdbcType=BIGINT}, " +
            "    </if> " +
            "    <if test=\"updateTime != null  \"> " +
            "        #{updateTime,jdbcType=TIMESTAMP}, " +
            "    </if> " +
            "    <if test=\"isDeleted != null \"> " +
            "        #{isDeleted,jdbcType=TINYINT}, " +
            "    </if> " +
            "</trim>" +
            "</script>")
    int insert(SysGroupUser groupUser);

    /**
     * 批量删除用户和用户组对应
     *
     * @param userId
     * @param groupIds
     * @return
     */
    @Delete("<script>" +
            "delete from sys_group_user " +
            "where user_id = #{userId,jdbcType=BIGINT} and group_id in " +
            "<foreach item=\"item\" collection=\"groupIds\" open=\"(\" separator=\",\" close=\")\"> " +
            "    #{item} " +
            "</foreach>" +
            "</script>")
    int removeByUserIdAndGroupIds(@Param("userId") Long userId, @Param("groupIds") List<Long> groupIds);

}
