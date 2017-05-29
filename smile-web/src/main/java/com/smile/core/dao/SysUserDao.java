package com.smile.core.dao;

import com.smile.core.domain.SysUser;
import com.smile.sharding.page.Pagination;
import org.apache.ibatis.annotations.*;
import org.apache.ibatis.mapping.StatementType;

import java.util.List;

/**
 * Created by zhutao on 2016/7/16.
 */
@Mapper
public interface SysUserDao {


    @Select("<script>" +
            "select * from sys_user <where> is_deleted = 0 " +
            "<if test=\"user.loginName !=null and user.loginName != ''\"> " +
            "   and login_name = #{user.loginName} " +
            "</if> " +
            "<if test=\"user.department !=null and user.department != ''\"> " +
            "    and department = #{user.department} " +
            "</if> " +
            "</where> " +
            "</script> ")
    List<SysUser> selectList(@Param("user") SysUser user, @Param("page") Pagination<SysUser> pagination);

    @Insert("<script>" +
            "insert into sys_user " +
            "<trim prefix=\"(\" suffix=\")\" suffixOverrides=\",\"> " +
            "<if test=\"id != null  \"> " +
            "id, " +
            "</if> " +
            "<if test=\"loginName != null  and loginName != ''\"> " +
            "login_name, " +
            "</if> " +
            "<if test=\"password != null  and password != ''\"> " +
            "password, " +
            "</if> " +
            "<if test=\"salt != null  and salt != ''\"> " +
            "salt, " +
            "</if> " +
            "<if test=\"fullName != null  and fullName != ''\"> " +
            "full_name, " +
            "</if> " +
            "<if test=\"userType != null  \"> " +
            " user_type, " +
            "</if> " +
            "<if test=\"gender != null   \"> " +
            "gender, " +
            "</if> " +
            "<if test=\"email != null  and email != ''\"> " +
            "email, " +
            "</if> " +
            "<if test=\"address != null  and address != ''\"> " +
            "address, " +
            "</if> " +
            "<if test=\"mobilePhone != null  and mobilePhone != ''\"> " +
            "mobile_phone, " +
            "</if> " +
            "<if test=\"telephone != null  and telephone != '' \"> " +
            "telephone, " +
            "</if> " +
            "<if test=\"loginRetry != null  and loginRetry != ''\"> " +
            "login_retry, " +
            "</if> " +
            "<if test=\"department != null  and department != ''\"> " +
            "department, " +
            "</if> " +
            "<if test=\"companyId != null  \"> " +
            "company_id, " +
            "</if> " +
            "<if test=\"lastLoginTime != null  \"> " +
            "last_login_time, " +
            "</if> " +
            "<if test=\"createdBy != null  \"> " +
            "created_by, " +
            "</if> " +
            "<if test=\"createTime != null  \"> " +
            "create_time, " +
            "</if> " +
            "<if test=\"updatedBy != null  \"> " +
            "updated_by, " +
            "</if> " +
            "<if test=\"updateTime != null  \"> " +
            "update_time, " +
            "</if> " +
            "<if test=\"isDeleted != null  \"> " +
            "is_deleted, " +
            "</if> " +
            "</trim> " +
            "<trim prefix=\"values (\" suffix=\")\" suffixOverrides=\",\"> " +
            "<if test=\"id != null \"> " +
            "#{id,jdbcType=BIGINT}, " +
            "</if> " +
            "<if test=\"loginName != null and loginName != ''\"> " +
            "#{loginName,jdbcType=VARCHAR}, " +
            "</if> " +
            "<if test=\"password != null and password != ''\"> " +
            "#{password,jdbcType=VARCHAR}, " +
            "</if> " +
            "<if test=\"salt != null and salt != ''\"> " +
            "#{salt,jdbcType=VARCHAR}, " +
            "</if> " +
            "<if test=\"fullName != null and fullName != ''\"> " +
            "#{fullName,jdbcType=VARCHAR}, " +
            "</if> " +
            "<if test=\"userType != null  \"> " +
            "#{userType,jdbcType=TINYINT}, " +
            "</if> " +
            "<if test=\"gender != null  \"> " +
            "#{gender,jdbcType=VARCHAR}, " +
            "</if> " +
            "<if test=\"email != null and email != ''\"> " +
            "#{email,jdbcType=VARCHAR}, " +
            "</if> " +
            "<if test=\"address != null and address != ''\"> " +
            "#{address,jdbcType=VARCHAR}, " +
            "</if> " +
            "<if test=\"mobilePhone != null and mobilePhone != ''\"> " +
            "#{mobilePhone,jdbcType=VARCHAR}, " +
            "</if> " +
            "<if test=\"telephone != null and telephone != ''\"> " +
            "#{telephone,jdbcType=VARCHAR}, " +
            "</if> " +
            "<if test=\"loginRetry != null and loginRetry != ''\"> " +
            "#{loginRetry,jdbcType=TINYINT}, " +
            "</if> " +
            "<if test=\"department != null and department != ''\"> " +
            "#{department,jdbcType=VARCHAR}, " +
            "</if> " +
            "<if test=\"companyId != null  \"> " +
            "#{companyId,jdbcType=BIGINT}, " +
            "</if> " +
            "<if test=\"lastLoginTime != null  \"> " +
            "#{lastLoginTime,jdbcType=TIMESTAMP}, " +
            "</if> " +
            "<if test=\"createdBy != null \"> " +
            "#{createdBy,jdbcType=BIGINT}, " +
            "</if> " +
            "<if test=\"createTime != null \"> " +
            "#{createTime,jdbcType=TIMESTAMP}, " +
            "</if> " +
            "<if test=\"updatedBy != null  \"> " +
            "#{updatedBy,jdbcType=BIGINT}, " +
            "</if> " +
            "<if test=\"updateTime != null  \"> " +
            "#{updateTime,jdbcType=TIMESTAMP}, " +
            "</if> " +
            "<if test=\"isDeleted != null   \"> " +
            "#{isDeleted,jdbcType=TINYINT}, " +
            "</if> " +
            "</trim> " +
            "</script> ")
    @SelectKey(before = false, keyProperty = "id", resultType = Long.class, statementType = StatementType.STATEMENT, statement = "SELECT LAST_INSERT_ID() AS id")
    void addUser(SysUser user);

    @Select("select * from sys_user where id = #{userId} and is_deleted = 0")
    SysUser selectById(@Param("userId") long userId);

    @Update("<script> update sys_user " +
            "<set> " +
            "<if test=\"loginName != null and loginName != '' \"> " +
            "login_name = #{loginName,jdbcType=VARCHAR}, " +
            "</if> " +
            "<if test=\"fullName != null and fullName != ''\"> " +
            "full_name = #{fullName,jdbcType=VARCHAR}, " +
            "</if> " +
            "<if test=\"gender != null  \"> " +
            "gender = #{gender,jdbcType=VARCHAR}, " +
            "</if> " +
            "<if test=\"email != null and email != ''\">" +
            "email = #{email,jdbcType=VARCHAR}," +
            "</if>" +
            "<if test=\"address != null and address != ''\"> " +
            "address = #{address,jdbcType=VARCHAR}, " +
            "</if> " +
            "<if test=\"mobilePhone != null and mobilePhone != ''\"> " +
            "mobile_phone = #{mobilePhone,jdbcType=VARCHAR}, " +
            "</if> " +
            "<if test=\"telephone != null and telephone != ''\"> " +
            "telephone = #{telephone,jdbcType=VARCHAR}, " +
            "</if> " +
            "<if test=\"loginRetry != null and loginRetry != ''\"> " +
            " login_retry = #{loginRetry,jdbcType=TINYINT}, " +
            "</if> " +
            "<if test=\"department != null and department != ''\"> " +
            "department = #{department,jdbcType=VARCHAR}, " +
            "</if> " +
            "<if test=\"companyId != null  \"> " +
            "company_id = #{companyId,jdbcType=BIGINT}, " +
            "</if> " +
            "<if test=\"lastLoginTime != null  \"> " +
            "last_login_time = #{lastLoginTime,jdbcType=TIMESTAMP}, " +
            "</if> " +
            "<if test=\"updatedBy != null \"> " +
            "updated_by = #{updatedBy,jdbcType=BIGINT}, " +
            "</if> " +
            "<if test=\"updateTime != null\"> " +
            "update_time = #{updateTime,jdbcType=TIMESTAMP}, " +
            "</if> " +
            "<if test=\"isDeleted != null\">" +
            "is_deleted = #{isDeleted,jdbcType=TINYINT}, " +
            "</if> " +
            "</set> " +
            "where id = #{id,jdbcType=BIGINT}</script> ")
    void updateUser(SysUser user);

    @Update("<script>" +
            "update sys_user " +
            "set is_deleted=1 " +
            "where id in " +
            "<foreach item=\"item\" collection=\"list\" open=\"(\" separator=\",\" close=\")\"> " +
            "#{item} " +
            " </foreach> " +
            "</script>")
    void deleteUser(List<Long> userIds);


    /**
     * 通过登陆名查询用户基本信息包含密码
     */
    @Select(" select id,salt, login_name, password,user_type, full_name, gender, email, address, mobile_phone, " +
            " telephone, login_retry, department, last_login_time, created_by, create_time, updated_by, " +
            " update_time, is_deleted " +
            "from sys_user " +
            "where login_name = #{loginName} ")
    SysUser selectByUserNameForPassword(@Param("loginName") String loginName);

}
