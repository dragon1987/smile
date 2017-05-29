package com.smile.core.dao;


import com.smile.core.domain.SysPermission;
import org.apache.ibatis.annotations.*;
import org.apache.ibatis.mapping.StatementType;

import java.util.Collection;
import java.util.List;

@Mapper
public interface SysPermissionDao {


    /**
     * 通过用户Id查询权限
     *
     * @param userId
     * @return
     */
    @Select("select  id, code, name, level, level_order levelOrder, parent_id pId, menu_level menuLevel, menu_url menuUrl,system_id,is_hidden, is_public_function,created_by, create_time, updated_by, update_time, is_deleted,menu_icon " +
            "from sys_permission where id in (select permission_id from sys_role_permission where role_id in " +
            "(select " +
            " id " +
            " from sys_role r " +
            " where r.id in ( " +
            " select role_id from sys_user_role rUser where rUser.user_id = #{userId} " +
            " union all " +
            " select role_id from sys_group_role gRole where gRole.group_id in ( " +
            " select role_id from sys_group_user gUser where gUser.user_id = #{userId} " +
            " ) " +
            " ) " +
            ")) " +
            "and is_deleted=0")
    List<SysPermission> selectByUserId(Long userId);

    @Select("select  id, code, name, level, level_order, parent_id pId, menu_level, menu_url,system_id,is_hidden, is_public_function,created_by, " +
            "create_time, updated_by, update_time, is_deleted,menu_icon  from sys_permission where is_deleted =0")
    List<SysPermission> selectList();

    @Insert("<script>" +
            "insert into sys_permission " +
            "<trim prefix=\"(\" suffix=\")\" suffixOverrides=\",\"> " +
            "    <if test=\"id != null \"> " +
            "        id, " +
            "    </if> " +
            "    <if test=\"code != null  and code != ''\"> " +
            "        code, " +
            "    </if> " +
            "    <if test=\"name != null  and name != ''\"> " +
            "        name, " +
            "    </if> " +
            "    <if test=\"level != null   \"> " +
            "        level, " +
            "    </if> " +
            "    <if test=\"levelOrder != null   \"> " +
            "        level_order, " +
            "    </if> " +
            "    <if test=\"pId != null\"> " +
            "        parent_id, " +
            "    </if> " +
            "    <if test=\"menuLevel != null  \"> " +
            "        menu_level, " +
            "    </if> " +
            "    <if test=\"menuUrl != null  and menuUrl != ''\"> " +
            "        menu_url, " +
            "    </if> " +
            "    <if test=\"systemId != null  and systemId != ''\"> " +
            "        system_id, " +
            "    </if> " +
            "    <if test=\"isHidden != 0\"> " +
            "        is_hidden, " +
            "    </if> " +
            "    <if test=\"isPublicFunction != 0 \"> " +
            "        is_public_function, " +
            "    </if> " +
            "    <if test=\"createdBy != null   \"> " +
            "        created_by, " +
            "    </if> " +
            "    <if test=\"createTime != null  \"> " +
            "        create_time, " +
            "    </if> " +
            "    <if test=\"updatedBy != null   \"> " +
            "        updated_by, " +
            "    </if> " +
            "    <if test=\"updateTime != null  \"> " +
            "        update_time, " +
            "    </if> " +
            "    <if test=\"isDeleted != null  \"> " +
            "        is_deleted, " +
            "    </if> " +
            "    <if test=\"menuIcon != null  \"> " +
            "        menu_icon, " +
            "    </if> " +
            "</trim> " +
            "<trim prefix=\"values (\" suffix=\")\" suffixOverrides=\",\"> " +
            "    <if test=\"id != null  \"> " +
            "        #{id,jdbcType=BIGINT}, " +
            "    </if> " +
            "    <if test=\"code != null and code != ''\"> " +
            "        #{code,jdbcType=VARCHAR}, " +
            "    </if> " +
            "    <if test=\"name != null and name != ''\"> " +
            "        #{name,jdbcType=VARCHAR}, " +
            "    </if> " +
            "    <if test=\"level != null  \"> " +
            "        #{level,jdbcType=TINYINT}, " +
            "    </if> " +
            "    <if test=\"levelOrder != null  \"> " +
            "        #{levelOrder,jdbcType=TINYINT}, " +
            "    </if> " +
            "    <if test=\"pId != null\"> " +
            "        #{pId,jdbcType=BIGINT}, " +
            "    </if> " +
            "    <if test=\"menuLevel != null  \"> " +
            "        #{menuLevel,jdbcType=TINYINT}, " +
            "    </if> " +
            "    <if test=\"menuUrl != null and menuUrl != ''\"> " +
            "        #{menuUrl,jdbcType=VARCHAR}, " +
            "    </if> " +
            "    <if test=\"systemId != null and systemId != ''\"> " +
            "        #{systemId,jdbcType=VARCHAR}, " +
            "    </if> " +
            "    <if test=\"isHidden != 0\"> " +
            "        #{isHidden,jdbcType=TINYINT}, " +
            "    </if> " +
            "    <if test=\"isPublicFunction != 0 \"> " +
            "        #{isPublicFunction,jdbcType=TINYINT}, " +
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
            "    <if test=\"isDeleted != null  \"> " +
            "        #{isDeleted,jdbcType=TINYINT}, " +
            "    </if> " +
            "    <if test=\"menuIcon!= null  \"> " +
            "        #{menuIcon,jdbcType=VARCHAR}, " +
            "    </if> " +
            "</trim>" +
            "</script>")
    @SelectKey(before = false, keyProperty = "id", resultType = Long.class, statementType = StatementType.STATEMENT, statement = "SELECT LAST_INSERT_ID() AS id")
    void add(SysPermission permission);


    @Update("<script>" +
            "update sys_permission " +
            "<set> " +
            "    <if test=\"code != null  and code != ''\"> " +
            "        code = #{code,jdbcType=VARCHAR}, " +
            "    </if> " +
            "    <if test=\"name != null  and name != ''\"> " +
            "        name = #{name,jdbcType=VARCHAR}, " +
            "    </if> " +
            "    <if test=\"level != null  \"> " +
            "        level = #{level,jdbcType=TINYINT}, " +
            "    </if> " +
            "    <if test=\"levelOrder != null  \"> " +
            "        level_order = #{levelOrder,jdbcType=TINYINT}, " +
            "    </if> " +
            "    <if test=\"pId != null\"> " +
            "        parent_id = #{pId,jdbcType=BIGINT}, " +
            "    </if> " +
            "    <if test=\"menuLevel != null  \"> " +
            "        menu_level = #{menuLevel,jdbcType=TINYINT}, " +
            "    </if> " +
            "    <if test=\"menuUrl != null  and menuUrl != ''\"> " +
            "        menu_url = #{menuUrl,jdbcType=VARCHAR}, " +
            "    </if> " +
            "    <if test=\"systemId != null  and systemId != ''\"> " +
            "        system_id = #{systemId,jdbcType=VARCHAR}, " +
            "    </if> " +
            "     is_hidden = #{isHidden,jdbcType=TINYINT}, " +
            "     is_public_function = #{isPublicFunction,jdbcType=TINYINT}, " +
            "    <if test=\"createdBy != null  \"> " +
            "        created_by = #{createdBy,jdbcType=BIGINT}, " +
            "    </if> " +
            "    <if test=\"createTime != null   \"> " +
            "        create_time = #{createTime,jdbcType=TIMESTAMP}, " +
            "    </if> " +
            "    <if test=\"updatedBy != null   \"> " +
            "        updated_by = #{updatedBy,jdbcType=BIGINT}, " +
            "    </if> " +
            "    <if test=\"updateTime != null  \"> " +
            "        update_time = #{updateTime,jdbcType=TIMESTAMP}, " +
            "    </if> " +
            "    <if test=\"isDeleted != null   \"> " +
            "        is_deleted = #{isDeleted,jdbcType=TINYINT}, " +
            "    </if> " +
            "    <if test=\"menuIcon != null  \"> " +
            "        menu_icon =#{menuIcon,jdbcType=VARCHAR}, " +
            "    </if> " +
            "</set> " +
            "where id = #{id,jdbcType=BIGINT}" +
            "</script>")
    void update(SysPermission permission);


    /**
     * 批量删除权限
     *
     * @param ids
     * @return
     */
    @Delete("<script>" +
            "delete from sys_permission " +
            "where id in " +
            "<foreach item=\"item\" collection=\"list\" open=\"(\" separator=\",\" close=\")\"> " +
            "    #{item} " +
            "</foreach></script>")
    int removeByIds(Collection<Long> ids);

    @Select("<script>   select " +
            "id, code, name, level, level_order, parent_id pId, menu_level, menu_url,system_id,is_hidden, is_public_function,created_by, " +
            "create_time, updated_by, update_time, is_deleted,menu_icon " +
            "from sys_permission " +
            "where id in (select permission_id from sys_role_permission where role_id = #{roleId,jdbcType=BIGINT}) and " +
            "is_deleted=0" +
            "</script>")
    List<SysPermission> selectByRoleId(@Param("roleId") Long roleId);

    /**
     * 通过角色编码查询权限
     *
     * @param roleCodes
     * @return
     */
     @Select("<script>" +
             "select " +
             "id, code, name, level, level_order, parent_id pId, menu_level, menu_url,system_id,is_hidden, is_public_function,created_by, " +
             "create_time, updated_by, update_time, is_deleted,menu_icon " +
             "from sys_permission " +
             "where id in (select permission_id from sys_role_permission where role_id in ( " +
             "select id from sys_role where " +
             "is_deleted=0 and code in " +
             "<foreach item=\"item\" collection=\"roleCodes\" open=\"(\" separator=\",\" close=\")\"> " +
             "    #{item} " +
             "</foreach> " +
             ")) and " +
             "is_deleted=0" +
             "</script>")
     List<SysPermission> selectByRoleCodes(@Param("roleCodes") List<String> roleCodes);

    /**
     * 通过角色编码查询权限
     *
     * @param roleCode
     * @return
     */
    @Select("<script>" +
            "select " +
            "id, code, name, level, level_order, parent_id pId, menu_level, menu_url,system_id,is_hidden, is_public_function,created_by, " +
            "create_time, updated_by, update_time, is_deleted,menu_icon " +
            "from sys_permission " +
            "where id in (select permission_id from sys_role_permission where role_id in ( " +
            "select id from sys_role where " +
            "is_deleted=0 and code =#{roleCode} " +
            ")) and " +
            "is_deleted=0" +
            "</script>")
    List<SysPermission> selectByRoleCode(@Param("roleCode") String roleCode);

}
