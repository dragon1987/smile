package com.smile.core.shiro;

import com.smile.core.domain.SysPermission;
import com.smile.core.domain.SysRole;
import com.smile.core.domain.SysUser;
import com.smile.core.service.SysPermissionService;
import com.smile.core.service.SysRoleService;
import com.smile.core.service.SysUserService;
import com.smile.core.utils.UserHolder;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.beans.factory.annotation.Autowired;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class UserRealm extends AuthorizingRealm {

    @Autowired
    private SysUserService userService;

    @Autowired
    private SysRoleService roleService;

    @Autowired
    private SysPermissionService permissionService;


    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        String username = (String) token.getPrincipal();
        SysUser user = userService.selectByUserNameForPassword(username);
        if (user == null) {
            throw new UnknownAccountException("账号不存在");//没找到帐号
        }
        PrincipalCollection principalCollection = new SimplePrincipalCollection(user, getName());
        return new SimpleAuthenticationInfo(principalCollection, user.getPassword(), ByteSource.Util.bytes(user.getLoginName() + user.getSalt()), getName());
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        authorizationInfo.setRoles(filterAuthorizationRoles(principals));
        authorizationInfo.setStringPermissions(filterAuthorizationPermissions(principals, new HashSet<String>()));
        return authorizationInfo;
    }


    public Set<String> filterAuthorizationRoles(PrincipalCollection principals) {
        SysUser user = UserHolder.getCurrentUser();
        Set<String> roleCodes = new HashSet<String>();
        if (user.getId() != null) {
            List<SysRole> sysRoles = roleService.findAllRolesByUserId(user.getId());
            if (sysRoles != null && !sysRoles.isEmpty()) {
                for (SysRole sysRole : sysRoles) {
                    roleCodes.add(sysRole.getCode());
                }
            }
        }
        return roleCodes;
    }


    public Set<String> filterAuthorizationPermissions(PrincipalCollection principals, Set<String> defaultRoleCodes) {
        Set<String> roleCodes = new HashSet<String>();
        Set<String> permissionCodes = new HashSet<String>();
        roleCodes.addAll(filterAuthorizationRoles(principals));
        roleCodes.addAll(defaultRoleCodes);
        if (roleCodes != null && !roleCodes.isEmpty()) {
            List<String> roleCodeList = new ArrayList<String>();
            for (String roleCode : roleCodes) {
                roleCodeList.add(roleCode);
            }
            List<SysPermission> permissions = permissionService.findByRoleCodes(roleCodeList);
            for (SysPermission permission : permissions) {
                permissionCodes.add(permission.getCode());
            }
            return permissionCodes;
        } else {
            return null;
        }
    }

    @Override
    public void clearCachedAuthorizationInfo(PrincipalCollection principals) {
        super.clearCachedAuthorizationInfo(principals);
    }

    @Override
    public void clearCachedAuthenticationInfo(PrincipalCollection principals) {
        super.clearCachedAuthenticationInfo(principals);
    }

    @Override
    public void clearCache(PrincipalCollection principals) {
        super.clearCache(principals);
    }

    public void clearAllCachedAuthorizationInfo() {
        getAuthorizationCache().clear();
    }

    public void clearAllCachedAuthenticationInfo() {
        getAuthenticationCache().clear();
    }

    public void clearAllCache() {
        clearAllCachedAuthenticationInfo();
        clearAllCachedAuthorizationInfo();
    }


    public void setUserService(SysUserService userService) {
        this.userService = userService;
    }

    public void setRoleService(SysRoleService roleService) {
        this.roleService = roleService;
    }

    public void setPermissionService(SysPermissionService permissionService) {
        this.permissionService = permissionService;
    }

}