package com.smile.core.domain;



import java.util.Date;

public class SysUser extends Entity {
    /**
     * 登陆名
     */
    private String loginName;

    /**
     * 密码
     */
    private String password;


    /**
     * 加密盐
     */
    private String salt;

    /**
     * 姓名
     */
    private String fullName;


    /**
     * 性别
     */
    private String gender;

    /**
     * 邮箱
     */
    private String email;

    /**
     * 地址
     */
    private String address;

    /**
     * 手机号码
     */
    private String mobilePhone;

    /**
     * 固定电话
     */
    private String telephone;

    /**
     * 失败登陆次数
     */
    private Integer loginRetry;

    /**
     * 部门
     */
    private String department;

    /**
     * 公司id
     */
    private Long companyId;

    /**
     * 最后登陆时间
     */
    private Date lastLoginTime;

    /**
     * 用户类别：主要指定用户来源，0：db，1：域账号
     */
    private Integer userType;

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }


    public String getLoginName() {
        return loginName;
    }

    public void setLoginName(String loginName) {
        this.loginName = loginName == null ? null : loginName.trim();
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password == null ? null : password.trim();
    }

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName == null ? null : fullName.trim();
    }

    public String getGender() {
        return gender;
    }

    public void setGender(String gender) {
        this.gender = gender == null ? null : gender.trim();
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email == null ? null : email.trim();
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address == null ? null : address.trim();
    }

    public String getMobilePhone() {
        return mobilePhone;
    }

    public void setMobilePhone(String mobilePhone) {
        this.mobilePhone = mobilePhone == null ? null : mobilePhone.trim();
    }

    public String getTelephone() {
        return telephone;
    }

    public void setTelephone(String telephone) {
        this.telephone = telephone == null ? null : telephone.trim();
    }

    public Integer getLoginRetry() {
        return loginRetry;
    }

    public void setLoginRetry(Integer loginRetry) {
        this.loginRetry = loginRetry;
    }

    public String getDepartment() {
        return department;
    }

    public void setDepartment(String department) {
        this.department = department == null ? null : department.trim();
    }

    public Date getLastLoginTime() {
        return lastLoginTime;
    }

    public void setLastLoginTime(Date lastLoginTime) {
        this.lastLoginTime = lastLoginTime;
    }


    public Integer getUserType() {
        return userType;
    }

    public void setUserType(Integer userType) {
        this.userType = userType;
    }

    public String getCredentialsSalt() {
        return loginName + salt;
    }

    public Long getCompanyId() {
        return companyId;
    }

    public void setCompanyId(Long companyId) {
        this.companyId = companyId;
    }
}