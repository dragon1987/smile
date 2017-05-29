package com.smile.core.dao;

import com.smile.core.domain.SysRole;
import com.smile.sharding.page.Pagination;
import org.apache.ibatis.annotations.*;

import java.util.List;

/**
 * Created by zhutao on 2016/7/31.
 */
@Mapper
public interface SysRoleDao {

    @Select("<script>" +
            "select * from sys_role <where> is_deleted = 0 " +
            "<if test=\"role.name !=null and role.name != ''\"> " +
            "   and name = #{role.name} " +
            "</if> " +
            "</where> " +
            "</script> ")
    List<SysRole> selectList(@Param("role") SysRole role, @Param("page") Pagination<SysRole> pagination);

    @Insert("<script>" +
            "insert into sys_role " +
            "<trim prefix=\"(\" suffix=\")\" suffixOverrides=\",\"> " +
            "<if test=\"id != null   \"> " +
            " id, " +
            "</if> " +
            "<if test=\"name != null  and name != ''\"> " +
            "   name, " +
            "</if> " +
            "<if test=\"code != null  and code != ''\"> " +
            "  code, " +
            "</if> " +
            "<if test=\"createdBy != null \"> " +
            "   created_by, " +
            "</if> " +
            "<if test=\"createTime != null  \"> " +
            "   create_time, " +
            "</if> " +
            "<if test=\"updatedBy != null   \"> " +
            "   updated_by, " +
            "</if> " +
            "<if test=\"updateTime != null   \"> " +
            "  update_time, " +
            "</if> " +
            "<if test=\"isDeleted != null   \"> " +
            "    is_deleted, " +
            "</if> " +
            "</trim> " +
            "<trim prefix=\"values (\" suffix=\")\" suffixOverrides=\",\"> " +
            "<if test=\"id != null   \"> " +
            "    #{id,jdbcType=BIGINT}, " +
            "</if> " +
            "<if test=\"name != null  and name != ''\"> " +
            "    #{name,jdbcType=VARCHAR}, " +
            "</if> " +
            "<if test=\"code != null  and code != ''\"> " +
            "    #{code,jdbcType=VARCHAR}, " +
            "</if> " +
            "<if test=\"createdBy != null   \"> " +
            "   #{createdBy,jdbcType=BIGINT}, " +
            "</if> " +
            "<if test=\"createTime != null  \"> " +
            "   #{createTime,jdbcType=TIMESTAMP}, " +
            "</if> " +
            "<if test=\"updatedBy != null   \"> " +
            "    #{updatedBy,jdbcType=BIGINT}, " +
            "</if> " +
            "<if test=\"updateTime != null   \"> " +
            "  #{updateTime,jdbcType=TIMESTAMP}, " +
            "</if> " +
            "<if test=\"isDeleted != null   \"> " +
            "   #{isDeleted,jdbcType=TINYINT}, " +
            "</if> " +
            "</trim>" +
            "</script> ")
    void addRole(SysRole role);

    @Select("select * from sys_role where id = #{roleId} and is_deleted = 0")
    SysRole selectById(@Param("roleId") long roleId);

    @Update("<script>" +
            "update sys_role " +
            "<set> " +
            "<if test=\"name != null and name != ''\"> " +
            "    name = #{name,jdbcType=VARCHAR}, " +
            "</if> " +
            "<if test=\"code != null and code != ''\"> " +
            "    code = #{code,jdbcType=VARCHAR}, " +
            "</if> " +
            "<if test=\"createdBy != null  \"> " +
            "    created_by = #{createdBy,jdbcType=BIGINT}, " +
            "</if> " +
            "<if test=\"createTime != null  \"> " +
            "    create_time = #{createTime,jdbcType=TIMESTAMP}, " +
            "</if> " +
            "<if test=\"updatedBy != null \"> " +
            "    updated_by = #{updatedBy,jdbcType=BIGINT}, " +
            "</if> " +
            "<if test=\"updateTime != null  \"> " +
            "    update_time = #{updateTime,jdbcType=TIMESTAMP}, " +
            "</if> " +
            "<if test=\"isDeleted != null \"> " +
            "    is_deleted = #{isDeleted,jdbcType=TINYINT}, " +
            "</if> " +
            "</set> " +
            "where id = #{id,jdbcType=BIGINT}" +
            "</script> ")
    void updateRole(SysRole role);

    @Update("<script>" +
            "update sys_role " +
            "set is_deleted=1 " +
            "where id in " +
            "<foreach item=\"item\" collection=\"list\" open=\"(\" separator=\",\" close=\")\"> " +
            "#{item} " +
            "</foreach> " +
            "</script>")
    void deleteRole(List<Long> ids);

    /**
     * 查询用户绑定角色
     *
     * @param userId
     * @param pagination
     * @return
     */
    @Select("select " +
            "r.id, r.name, r.code,  r.created_by, r.create_time, r.updated_by, r.update_time, is_deleted " +
            "from sys_role r " +
            "where r.id  in (select role_id from sys_user_role rUser where rUser.user_id = #{userId,jdbcType=BIGINT}) and r.is_deleted=0")
     List<SysRole> selectByUserId(@Param("userId") Long userId, Pagination pagination);

    @Select("<script>" +
            "select" +
            "r.id, r.name, r.code,r.created_by, r.create_time, r.updated_by, r.update_time, is_deleted " +
            "from sys_role r " +
            "where r.id not in (select role_id from sys_user_role rUser where rUser.user_id = #{userId,jdbcType=BIGINT}) " +
            "and r.is_deleted=0 " +
            "<if test=\"roleName != null and roleName != ''\"> " +
            "    and r.name=#{roleName} " +
            "</if>" +
            "</script>")
     List<SysRole> selectUnbindByUserId(@Param("userId")Long userId,@Param("roleName") String roleName, Pagination pagination);


    /**
     * 查询用的所有角色（包括用户组的角色）
     *
     * @param userId
     * @return
     */
     @Select("select " +
             "r.id, r.name, r.code,  r.created_by, r.create_time, r.updated_by, r.update_time, is_deleted " +
             "from sys_role r " +
             "where r.id  in ( " +
             "   select role_id from sys_user_role rUser where rUser.user_id = #{userId,jdbcType=BIGINT} " +
             "   union all " +
             "   select role_id from sys_group_role gRole where gRole.group_id in ( " +
             "        select role_id from sys_group_user gUser where gUser.user_id = #{userId,jdbcType=BIGINT} " +
             "     ) " +
             "   ) and r.is_deleted=0")
     List<SysRole> selectAllRolesByUserId(@Param("userId") Long userId);

}
