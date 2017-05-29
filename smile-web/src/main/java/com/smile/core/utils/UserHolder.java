package com.smile.core.utils;

import com.smile.core.domain.SysUser;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.Subject;

/**
 * Created by zhutao on 2016/8/13.
 */
public class UserHolder {

    public static SysUser getCurrentUser() {
        Subject subject = SecurityUtils.getSubject();
        return (SysUser) ((SimplePrincipalCollection) (subject).getPrincipal()).asList().get(0);
    }

    public static Long getCurrentUserId() {
        Subject subject = SecurityUtils.getSubject();
        SysUser user = (SysUser) ((SimplePrincipalCollection) (subject).getPrincipal()).asList().get(0);
        return user.getId();
    }
}
