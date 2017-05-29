/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.smile.core.shiro.configuration;

import com.smile.core.service.SysPermissionService;
import com.smile.core.service.SysRoleService;
import com.smile.core.service.SysUserService;
import com.smile.core.shiro.FormAuthenticationFilter;
import com.smile.core.shiro.RetryLimitHashedCredentialsMatcher;
import com.smile.core.shiro.UserRealm;

import org.apache.shiro.authc.credential.HashedCredentialsMatcher;

import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.cache.ehcache.EhCacheManager;

import org.apache.shiro.realm.Realm;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.spring.web.config.DefaultShiroFilterChainDefinition;
import org.apache.shiro.spring.web.config.ShiroFilterChainDefinition;
import org.apache.shiro.web.filter.authc.AuthenticationFilter;
import javax.servlet.Filter;
import  org.apache.shiro.mgt.SecurityManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;


/**
 * @since 1.4.0
 */
@Configuration
public class ShiroConfiguration {

    @Bean
    protected CacheManager cacheManager() {
        EhCacheManager ehCacheManager = new EhCacheManager();
        ehCacheManager.setCacheManagerConfigFile("classpath:ehcache.xml");
        return ehCacheManager;
    }

    @Bean
    protected HashedCredentialsMatcher hashedCredentialsMatcher(CacheManager cacheManager) {
        RetryLimitHashedCredentialsMatcher hashedCredentialsMatcher = new RetryLimitHashedCredentialsMatcher(
                cacheManager);
        hashedCredentialsMatcher.setHashAlgorithmName("md5");
        hashedCredentialsMatcher.setHashIterations(2);
        hashedCredentialsMatcher.setStoredCredentialsHexEncoded(true);
        return hashedCredentialsMatcher;
    }

    @Bean
    protected Realm authorizingRealm(HashedCredentialsMatcher credentialsMatcher,
                                                SysUserService userService,
                                                SysRoleService roleService,
                                                SysPermissionService permissionService) {
        UserRealm userRealm = new UserRealm();
        userRealm.setCredentialsMatcher(credentialsMatcher);
        userRealm.setAuthenticationCacheName("authorizationCache");
        userRealm.setAuthenticationCachingEnabled(true);
        userRealm.setCachingEnabled(true);
        userRealm.setUserService(userService);
        userRealm.setRoleService(roleService);
        userRealm.setPermissionService(permissionService);
        return userRealm;
    }


    @Bean
    public ShiroFilterChainDefinition shiroFilterChainDefinition() {
        DefaultShiroFilterChainDefinition chainDefinition = new DefaultShiroFilterChainDefinition();
        chainDefinition.addPathDefinition("/login", "authc");
        chainDefinition.addPathDefinition("/logout", "logout");
        chainDefinition.addPathDefinition("/css/**", "anon");
        chainDefinition.addPathDefinition("/fonts/**", "anon");
        chainDefinition.addPathDefinition("/framework/**", "anon");
        chainDefinition.addPathDefinition("/img/**", "anon");
        chainDefinition.addPathDefinition("/js/**", "anon");
        chainDefinition.addPathDefinition("/favicon.ico", "anon");
        chainDefinition.addPathDefinition("/wavelab/** ", "anon");
        chainDefinition.addPathDefinition("/** ", "user");
        return chainDefinition;
    }

    @Bean
    protected AuthenticationFilter authenticationFilter() {
        FormAuthenticationFilter authenticationFilter = new FormAuthenticationFilter();
        authenticationFilter.setPasswordParam("password");
        authenticationFilter.setUsernameParam("username");
        authenticationFilter.setLoginUrl("/login");
        authenticationFilter.setRememberMeParam("rememberMe");
        authenticationFilter.setFailureKeyAttribute("error");
        return authenticationFilter;
    }

    @Bean
    protected ShiroFilterFactoryBean shiroFilterFactoryBean(SecurityManager securityManager,
                                                            Filter authenticationFilter,ShiroFilterChainDefinition shiroFilterChainDefinition) {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        shiroFilterFactoryBean.setLoginUrl("/login");
        shiroFilterFactoryBean.setSuccessUrl("/");
        shiroFilterFactoryBean.setUnauthorizedUrl("/unauthorized");
        shiroFilterFactoryBean.setSecurityManager(securityManager);
        Map<String, Filter> filterMap = new HashMap<String, Filter>();
        filterMap.put("authc", authenticationFilter);
        shiroFilterFactoryBean.setFilters(filterMap);
        shiroFilterFactoryBean.setFilterChainDefinitionMap(shiroFilterChainDefinition.getFilterChainMap());
        return shiroFilterFactoryBean;
    }


//    @Bean
//    protected SessionIdGenerator sessionIdGenerator() {
//        return new JavaUuidSessionIdGenerator();
//    }
//
//    @Bean(name = "sessionIdCookie")
//    protected SimpleCookie simpleCookie() {
//        SimpleCookie cookie = new SimpleCookie("sid");
//        cookie.setHttpOnly(true);
//        cookie.setMaxAge(-1);
//        return cookie;
//    }
////
//    @Bean(name = "rememberMeCookie")
//    protected SimpleCookie rememberMeCookie() {
//        SimpleCookie cookie = new SimpleCookie("rememberMe");
//        cookie.setHttpOnly(true);
//        cookie.setMaxAge(2592000);
//        return cookie;
//    }
////
//    @Bean
//    protected CookieRememberMeManager rememberMeManager(SimpleCookie rememberMeCookie) {
//        CookieRememberMeManager rememberMeManager = new CookieRememberMeManager();
//        rememberMeManager.setCookie(rememberMeCookie);
//        rememberMeManager.setCipherKey(Base64.decode("4AvVhmFLUs0KTA3Kprsdag=="));
//        return rememberMeManager;
//    }
//
//    @Bean
//
//    protected EnterpriseCacheSessionDAO sessionDAO(SessionIdGenerator sessionIdGenerator) {
//        EnterpriseCacheSessionDAO cacheSessionDAO = new EnterpriseCacheSessionDAO();
//        cacheSessionDAO.setSessionIdGenerator(sessionIdGenerator);
//        cacheSessionDAO.setActiveSessionsCacheName("shiro-activeSessionCache");
//        return cacheSessionDAO;
//    }
//
//    @Bean
//    protected DefaultWebSessionManager sessionManager(SimpleCookie sessionIdCookie) {
//        DefaultWebSessionManager webSessionManager = new DefaultWebSessionManager();
//        webSessionManager.setSessionIdCookie(sessionIdCookie);
//        webSessionManager.setGlobalSessionTimeout(1800000);
//        webSessionManager.setSessionIdCookieEnabled(true);
//        webSessionManager.setDeleteInvalidSessions(true);
//        webSessionManager.setSessionValidationSchedulerEnabled(true);
////				webSessionManager.setSessionValidationScheduler(sessionValidationScheduler);
////				sessionValidationScheduler.setSessionManager(webSessionManager);
//        return webSessionManager;
//    }
//
////    @Bean
////    protected SessionValidationScheduler quartzSessionValidationScheduler(DefaultWebSessionManager sessionManager) {
////        QuartzSessionValidationScheduler sessionValidationScheduler = new QuartzSessionValidationScheduler();
////        sessionValidationScheduler.setSessionManager(sessionManager);
////        sessionValidationScheduler.setSessionValidationInterval(1000);
////        return sessionValidationScheduler;
////    }
//
//
//
//
//
//
//    @Bean
//    protected SecurityManager securityManager(AuthorizingRealm userRealm, SessionManager sessionManager,
//                                              CacheManager cacheManager, CookieRememberMeManager rememberMeManager) {
//        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
//        securityManager.setRealm(userRealm);
//        securityManager.setSessionManager(sessionManager);
//        securityManager.setCacheManager(cacheManager);
//        securityManager.setRememberMeManager(rememberMeManager);
//        return securityManager;
//    }
//
//    @Bean
//    protected MethodInvokingFactoryBean methodInvokingFactoryBean(SecurityManager securityManager) {
//        MethodInvokingFactoryBean methodInvokingFactoryBean = new MethodInvokingFactoryBean();
//        methodInvokingFactoryBean.setStaticMethod("org.apache.shiro.SecurityUtils.setSecurityManager");
//        methodInvokingFactoryBean.setArguments(new Object[]{securityManager});
//        return methodInvokingFactoryBean;
//    }
//

//
//    @Bean
//    public FilterRegistrationBean filterRegistrationBean() {
//        FilterRegistrationBean filterRegistration = new FilterRegistrationBean();
//        filterRegistration.setFilter(new DelegatingFilterProxy("shiroFilter"));
//        //  该值缺省为false,表示生命周期由SpringApplicationContext管理,设置为true则表示由ServletContainer管理
//        filterRegistration.addInitParameter("targetFilterLifecycle", "true");
//        filterRegistration.setEnabled(true);
//        filterRegistration.addUrlPatterns("/*");// 可以自己灵活的定义很多，避免一些根本不需要被Shiro处理的请求被包含进来
//        return filterRegistration;
//    }
//
//    @Bean("shiroFilter")
//    protected ShiroFilterFactoryBean shiroFilterFactoryBean(SecurityManager securityManager,
//                                                            Filter authenticationFilter) {
//        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
//        shiroFilterFactoryBean.setLoginUrl("/login");
//        shiroFilterFactoryBean.setUnauthorizedUrl("/unauthorized");
//        shiroFilterFactoryBean.setSecurityManager(securityManager);
//        Map<String, Filter> filterMap = new HashMap<String, Filter>();
//        filterMap.put("authc", authenticationFilter);
//        shiroFilterFactoryBean.setFilters(filterMap);
//        Map<String, String> filterChainDefinitionMap = new HashMap<String, String>();
//        filterChainDefinitionMap.put("/login", "anon");
//        filterChainDefinitionMap.put("/logout", "logout");
//        filterChainDefinitionMap.put("/statics/** ", "anon");
//        filterChainDefinitionMap.put("/resources/** ", "anon");
//        filterChainDefinitionMap.put("/wavelab/** ", "anon");
////		filterChainDefinitionMap.put("/authenticated", "authc");
//        filterChainDefinitionMap.put("/** ", "anon");
//        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
//        return shiroFilterFactoryBean;
//    }


}
