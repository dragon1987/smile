package com.smile.core.dao;

import com.smile.core.domain.SysGroup;
import com.smile.core.domain.SysRole;
import com.smile.sharding.page.Pagination;
import org.apache.ibatis.annotations.*;

import java.util.List;

/**
 * Created by zhutao on 2016/7/31.
 */
@Mapper
public interface SysGroupDao {

    @Select("<script>" +
            "select * from sys_group <where> is_deleted = 0 " +
            "<if test=\"group.name !=null and group.name != ''\"> " +
            "   and name = #{group.name} " +
            "</if> " +
            "</where> " +
            "</script> ")
    List<SysGroup> selectList(@Param("group") SysGroup group, @Param("page") Pagination<SysGroup> pagination);

    @Insert("<script>" +
            "insert into sys_group " +
            "<trim prefix=\"(\" suffix=\")\" suffixOverrides=\",\"> " +
            "    <if test=\"id != null   \"> " +
            "        id, " +
            "    </if> " +
            "    <if test=\"name != null  and name != ''\"> " +
            "        name, " +
            "    </if> " +
            "    <if test=\"code != null  and code != ''\"> " +
            "        code, " +
            "    </if> " +
            "    <if test=\"createdBy != null \"> " +
            "        created_by, " +
            "    </if> " +
            "    <if test=\"createTime != null  \"> " +
            "        create_time, " +
            "    </if> " +
            "    <if test=\"updatedBy != null   \"> " +
            "        updated_by, " +
            "    </if> " +
            "    <if test=\"updateTime != null   \"> " +
            "        update_time, " +
            "    </if> " +
            "    <if test=\"isDeleted != null   \"> " +
            "        is_deleted, " +
            "    </if> " +
            "</trim> " +
            "<trim prefix=\"values (\" suffix=\")\" suffixOverrides=\",\"> " +
            "    <if test=\"id != null   \"> " +
            "        #{id,jdbcType=BIGINT}, " +
            "    </if> " +
            "    <if test=\"name != null  and name != ''\"> " +
            "        #{name,jdbcType=VARCHAR}, " +
            "    </if> " +
            "    <if test=\"code != null  and code != ''\"> " +
            "        #{code,jdbcType=VARCHAR}, " +
            "    </if> " +
            "    <if test=\"createdBy != null   \"> " +
            "        #{createdBy,jdbcType=BIGINT}, " +
            "    </if> " +
            "    <if test=\"createTime != null  \"> " +
            "        #{createTime,jdbcType=TIMESTAMP}, " +
            "    </if> " +
            "    <if test=\"updatedBy != null   \"> " +
            "        #{updatedBy,jdbcType=BIGINT}, " +
            "    </if> " +
            "    <if test=\"updateTime != null   \"> " +
            "        #{updateTime,jdbcType=TIMESTAMP}, " +
            "    </if> " +
            "    <if test=\"isDeleted != null   \"> " +
            "        #{isDeleted,jdbcType=TINYINT}, " +
            "    </if> " +
            "</trim>" +
            "</script> ")
    void addGroup(SysGroup group);

    @Select("select * from sys_group where id = #{groupId} and is_deleted = 0")
    SysGroup selectById(@Param("groupId") long groupId);

    @Update("<script>" +
            "update sys_group " +
            "<set> " +
            "    <if test=\"name != null and name != ''\"> " +
            "        name = #{name,jdbcType=VARCHAR}, " +
            "    </if> " +
            "    <if test=\"code != null and code != ''\"> " +
            "        code = #{code,jdbcType=VARCHAR}, " +
            "    </if> " +
            "    <if test=\"createdBy != null  \"> " +
            "        created_by = #{createdBy,jdbcType=BIGINT}, " +
            "    </if> " +
            "    <if test=\"createTime != null  \"> " +
            "        create_time = #{createTime,jdbcType=TIMESTAMP}, " +
            "    </if> " +
            "    <if test=\"updatedBy != null \"> " +
            "        updated_by = #{updatedBy,jdbcType=BIGINT}, " +
            "    </if> " +
            "    <if test=\"updateTime != null  \"> " +
            "        update_time = #{updateTime,jdbcType=TIMESTAMP}, " +
            "    </if> " +
            "    <if test=\"isDeleted != null \"> " +
            "        is_deleted = #{isDeleted,jdbcType=TINYINT}, " +
            "    </if> " +
            "</set> " +
            "where id = #{id,jdbcType=BIGINT}" +
            "</script> ")
    void updateGroup(SysGroup group);

    @Update("<script>" +
            "update sys_group " +
            "set is_deleted=1 " +
            "where id in " +
            "<foreach item=\"item\" collection=\"list\" open=\"(\" separator=\",\" close=\")\"> " +
            "#{item} " +
            " </foreach> " +
            "</script>")
    void deleteGroup(List<Long> ids);


    /**
     * 通过用户id查询用户所属的用户组
     *
     * @param userId
     * @param pagination
     * @return
     */
    @Select("select " +
            "  g.id, g.code, g.name, g.created_by, g.create_time, g.updated_by, g.update_time, g.is_deleted " +
            "from sys_group g " +
            "where g.id  in (select group_id from sys_group_user gUser where gUser.user_id = #{userId,jdbcType=BIGINT}) and g.is_deleted=0")
    List<SysGroup> selectByUserId(@Param("userId") long userId, Pagination pagination);

    /**
     * 通过用户id查询用户未绑定的用户组
     *
     * @param userId
     * @param pagination
     * @return
     */
    @Select("<script>" +
            "select " +
            "g.id, g.code, g.name,g.created_by, g.create_time, g.updated_by, g.update_time, g.is_deleted " +
            "from sys_group g " +
            "where g.id not in (select group_id from sys_group_user gUser where gUser.user_id = #{userId,jdbcType=BIGINT}) " +
            "and " +
            "g.is_deleted=0 " +
            "<if test=\"name != null and name != ''\"> " +
            "    and name=#{name,jdbcType=VARCHAR} " +
            "</if>" +
            "</script>")
    List<SysGroup> selectUnBindByUserId(@Param("userId") long userId, @Param("name") String name, Pagination pagination);

}
