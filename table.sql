/*
Navicat MariaDB Data Transfer

Source Server         : 本地
Source Server Version : 100113
Source Host           : localhost:3306
Source Database       : test

Target Server Type    : MariaDB
Target Server Version : 100113
File Encoding         : 65001

Date: 2016-08-13 21:24:01
*/

SET FOREIGN_KEY_CHECKS=0;

-- ----------------------------
-- Table structure for sharding_ticket
-- ----------------------------
DROP TABLE IF EXISTS `sharding_ticket`;
CREATE TABLE `sharding_ticket` (
  `table_name` varchar(50) NOT NULL DEFAULT 'table',
  `table_seq` bigint(20) NOT NULL AUTO_INCREMENT,
  PRIMARY KEY (`table_name`,`table_seq`),
  UNIQUE KEY `table_name` (`table_name`) USING BTREE
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of sharding_ticket
-- ----------------------------
INSERT INTO `sharding_ticket` VALUES ('SUBSCRIBE_REQ', '121');
INSERT INTO `sharding_ticket` VALUES ('SYS_GROUP', '95');
INSERT INTO `sharding_ticket` VALUES ('SYS_GROUP_ROLE', '195');
INSERT INTO `sharding_ticket` VALUES ('SYS_GROUP_USER', '164');
INSERT INTO `sharding_ticket` VALUES ('SYS_PERMISSION', '174');
INSERT INTO `sharding_ticket` VALUES ('SYS_ROLE', '63');
INSERT INTO `sharding_ticket` VALUES ('SYS_ROLE_PERMISSION', '1414');
INSERT INTO `sharding_ticket` VALUES ('SYS_USER', '292');
INSERT INTO `sharding_ticket` VALUES ('SYS_USER_ROLE', '134');

-- ----------------------------
-- Table structure for sys_group
-- ----------------------------
DROP TABLE IF EXISTS `sys_group`;
CREATE TABLE `sys_group` (
  `ID` bigint(20) NOT NULL,
  `CODE` varchar(20) COLLATE utf8_bin NOT NULL COMMENT '代码',
  `NAME` varchar(50) COLLATE utf8_bin NOT NULL COMMENT '名称',
  `CREATED_BY` bigint(20) DEFAULT NULL COMMENT '创建人ID',
  `CREATE_TIME` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `UPDATED_BY` bigint(20) DEFAULT NULL COMMENT '修改人ID',
  `UPDATE_TIME` datetime DEFAULT NULL COMMENT '最后修改时间',
  `IS_DELETED` tinyint(4) DEFAULT '0' COMMENT '是否失效',
  PRIMARY KEY (`ID`),
  UNIQUE KEY `NAME_UNIQUE` (`NAME`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin COMMENT='用户组';

-- ----------------------------
-- Records of sys_group
-- ----------------------------

-- ----------------------------
-- Table structure for sys_group_role
-- ----------------------------
DROP TABLE IF EXISTS `sys_group_role`;
CREATE TABLE `sys_group_role` (
  `ID` bigint(20) NOT NULL,
  `GROUP_ID` bigint(20) NOT NULL COMMENT '用户组ID',
  `ROLE_ID` bigint(20) NOT NULL COMMENT '角色ID',
  `CREATED_BY` bigint(20) DEFAULT NULL COMMENT '创建人ID',
  `CREATE_TIME` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `UPDATED_BY` bigint(20) DEFAULT NULL COMMENT '修改人ID',
  `UPDATE_TIME` datetime DEFAULT NULL COMMENT '最后修改时间',
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- ----------------------------
-- Records of sys_group_role
-- ----------------------------

-- ----------------------------
-- Table structure for sys_group_user
-- ----------------------------
DROP TABLE IF EXISTS `sys_group_user`;
CREATE TABLE `sys_group_user` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `GROUP_ID` bigint(20) NOT NULL COMMENT '用户组ID',
  `USER_ID` bigint(20) NOT NULL COMMENT '用户ID',
  `CREATED_BY` bigint(20) DEFAULT NULL COMMENT '创建人ID',
  `CREATE_TIME` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `UPDATED_BY` bigint(20) DEFAULT NULL COMMENT '修改人ID',
  `UPDATE_TIME` datetime DEFAULT NULL COMMENT '最后修改时间',
  `IS_DELETED` tinyint(4) DEFAULT '0' COMMENT '是否失效',
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=176 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- ----------------------------
-- Records of sys_group_user
-- ----------------------------

-- ----------------------------
-- Table structure for sys_permission
-- ----------------------------
DROP TABLE IF EXISTS `sys_permission`;
CREATE TABLE `sys_permission` (
  `ID` bigint(20) NOT NULL,
  `CODE` varchar(100) DEFAULT NULL COMMENT '权限码（一般根据菜单的树形结果生成）',
  `NAME` varchar(100) DEFAULT NULL COMMENT '权限名称',
  `LEVEL` tinyint(4) DEFAULT NULL COMMENT '层级',
  `LEVEL_ORDER` tinyint(4) DEFAULT NULL COMMENT '层级顺序',
  `PARENT_ID` bigint(20) DEFAULT NULL COMMENT '父节点ID',
  `MENU_LEVEL` tinyint(4) DEFAULT NULL COMMENT '是否是菜单',
  `MENU_URL` varchar(255) DEFAULT NULL COMMENT '菜单URL地址',
  `CREATED_BY` bigint(20) DEFAULT NULL COMMENT '创建人ID',
  `CREATE_TIME` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `UPDATED_BY` bigint(20) DEFAULT NULL COMMENT '修改人ID',
  `UPDATE_TIME` datetime DEFAULT NULL COMMENT '最后修改时间',
  `IS_DELETED` tinyint(4) DEFAULT '0' COMMENT '是否失效',
  `MENU_ICON` varchar(255) DEFAULT NULL,
  `SYSTEM_ID` varchar(255) DEFAULT NULL,
  `IS_HIDDEN` tinyint(4) DEFAULT NULL,
  `is_public_function` tinyint(4) DEFAULT NULL,
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='权限表';

-- ----------------------------
-- Records of sys_permission
-- ----------------------------
INSERT INTO `sys_permission` VALUES ('22', 'role', '用户管理', '1', '1', '0', '1', 'role/index', '-1', '2015-01-06 12:17:21', '95', '2015-04-22 17:47:28', '0', 'icon-list', null, null, null);
INSERT INTO `sys_permission` VALUES ('25', 'user.user', '用户', '2', '1', '22', '2', 'user/index', '-1', '2015-01-06 13:09:36', '95', '2015-04-16 14:56:07', '0', '', '1111', '0', '0');
INSERT INTO `sys_permission` VALUES ('26', 'user.role', '角色', '2', '3', '22', '2', 'role/index', '-1', '2015-01-06 13:09:59', '105', '2015-01-22 12:24:58', '0', null, null, null, null);
INSERT INTO `sys_permission` VALUES ('27', 'user.menu', '菜单', '2', '4', '22', '2', 'menu/index', '-1', '2015-01-06 13:10:30', '95', '2015-04-16 14:54:28', '0', null, null, null, null);
INSERT INTO `sys_permission` VALUES ('79', 'user.role.find', '查询', '3', '1', '26', '3', '', '95', '2015-01-15 14:33:26', null, null, '0', null, null, null, null);
INSERT INTO `sys_permission` VALUES ('104', 'user.group', '用户组', '2', '2', '22', '2', 'group/index', '95', '2015-03-10 10:47:03', '95', '2015-04-16 14:57:41', '0', null, null, null, null);

-- ----------------------------
-- Table structure for sys_role
-- ----------------------------
DROP TABLE IF EXISTS `sys_role`;
CREATE TABLE `sys_role` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `NAME` varchar(50) DEFAULT NULL COMMENT '角色名',
  `CODE` varchar(50) DEFAULT NULL COMMENT '角色编码',
  `CREATED_BY` bigint(20) DEFAULT NULL COMMENT '创建人ID',
  `CREATE_TIME` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `UPDATED_BY` bigint(20) DEFAULT NULL COMMENT '修改人ID',
  `UPDATE_TIME` datetime DEFAULT NULL COMMENT '最后修改时间',
  `IS_DELETED` tinyint(4) DEFAULT '0' COMMENT '是否失效',
  PRIMARY KEY (`ID`),
  UNIQUE KEY `NAME_UNIQUE` (`NAME`)
) ENGINE=InnoDB AUTO_INCREMENT=58 DEFAULT CHARSET=utf8 COMMENT='角色表';

-- ----------------------------
-- Records of sys_role
-- ----------------------------
INSERT INTO `sys_role` VALUES ('12', '系统管理员', 'admin', '-1', '2015-01-07 14:07:19', '95', '2016-08-13 21:08:47', '0');
INSERT INTO `sys_role` VALUES ('16', '默认角色', 'default', '95', '2015-01-09 10:21:15', null, null, '0');

-- ----------------------------
-- Table structure for sys_role_permission
-- ----------------------------
DROP TABLE IF EXISTS `sys_role_permission`;
CREATE TABLE `sys_role_permission` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `PERMISSION_ID` bigint(20) DEFAULT NULL COMMENT '权限ID',
  `ROLE_ID` bigint(20) DEFAULT NULL COMMENT '角色ID',
  `CREATED_BY` bigint(20) DEFAULT NULL COMMENT '创建人ID',
  `CREATE_TIME` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `UPDATED_BY` bigint(20) DEFAULT NULL COMMENT '修改人ID',
  `UPDATE_TIME` datetime DEFAULT NULL COMMENT '最后修改时间',
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=434 DEFAULT CHARSET=utf8 COMMENT='角色权限表';

-- ----------------------------
-- Records of sys_role_permission
-- ----------------------------
INSERT INTO `sys_role_permission` VALUES ('354', '22', '12', null, '2016-08-05 23:24:02', null, null);
INSERT INTO `sys_role_permission` VALUES ('355', '25', '12', null, '2016-08-05 23:24:02', null, null);
INSERT INTO `sys_role_permission` VALUES ('356', '26', '12', null, '2016-08-05 23:24:02', null, null);
INSERT INTO `sys_role_permission` VALUES ('357', '79', '12', null, '2016-08-05 23:24:02', null, null);
INSERT INTO `sys_role_permission` VALUES ('358', '27', '12', null, '2016-08-05 23:24:02', null, null);
INSERT INTO `sys_role_permission` VALUES ('359', '104', '12', null, '2016-08-05 23:24:02', null, null);
INSERT INTO `sys_role_permission` VALUES ('394', '22', '16', null, '2016-08-06 09:00:16', null, null);
INSERT INTO `sys_role_permission` VALUES ('395', '25', '16', null, '2016-08-06 09:00:16', null, null);
INSERT INTO `sys_role_permission` VALUES ('396', '26', '16', null, '2016-08-06 09:00:16', null, null);
INSERT INTO `sys_role_permission` VALUES ('397', '79', '16', null, '2016-08-06 09:00:16', null, null);
INSERT INTO `sys_role_permission` VALUES ('398', '27', '16', null, '2016-08-06 09:00:16', null, null);
INSERT INTO `sys_role_permission` VALUES ('399', '104', '16', null, '2016-08-06 09:00:17', null, null);

-- ----------------------------
-- Table structure for sys_user
-- ----------------------------
DROP TABLE IF EXISTS `sys_user`;
CREATE TABLE `sys_user` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `LOGIN_NAME` varchar(50) DEFAULT NULL COMMENT '登陆名',
  `PASSWORD` varchar(50) DEFAULT NULL COMMENT '密码',
  `SALT` varchar(50) DEFAULT NULL COMMENT '加密盐',
  `FULL_NAME` varchar(50) DEFAULT NULL COMMENT '姓名',
  `GENDER` varchar(1) DEFAULT NULL COMMENT '性别',
  `EMAIL` varchar(200) DEFAULT NULL COMMENT '邮箱',
  `ADDRESS` varchar(200) DEFAULT NULL COMMENT '地址',
  `MOBILE_PHONE` varchar(20) DEFAULT NULL COMMENT '手机号码',
  `TELEPHONE` varchar(20) DEFAULT NULL COMMENT '固定电话',
  `LOGIN_RETRY` tinyint(4) DEFAULT NULL COMMENT '失败登陆次数',
  `DEPARTMENT` varchar(50) DEFAULT NULL COMMENT '部门',
  `USER_TYPE` tinyint(4) DEFAULT '0',
  `LAST_LOGIN_TIME` datetime DEFAULT NULL COMMENT '最后登陆时间',
  `CREATED_BY` bigint(20) DEFAULT NULL COMMENT '创建人ID',
  `CREATE_TIME` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `UPDATED_BY` bigint(20) DEFAULT NULL COMMENT '修改人ID',
  `UPDATE_TIME` datetime DEFAULT NULL COMMENT '最后修改时间',
  `IS_DELETED` tinyint(4) DEFAULT '0' COMMENT '是否失效',
  PRIMARY KEY (`ID`),
  UNIQUE KEY `loginUnique` (`LOGIN_NAME`,`USER_TYPE`)
) ENGINE=InnoDB AUTO_INCREMENT=413 DEFAULT CHARSET=utf8 COMMENT='用户信息表';

-- ----------------------------
-- Records of sys_user
-- ----------------------------
INSERT INTO `sys_user` VALUES ('95', 'zhutao', '78fdf168d5664dd5c6d0d94ed25b0e22', '647bf2e4de2fd1abb4acfc790367f75a', null, '0', null, null, null, null, null, null, '1', null, '-1', '2015-01-07 14:56:43', '95', '2015-01-19 11:05:21', '0');

-- ----------------------------
-- Table structure for sys_user_role
-- ----------------------------
DROP TABLE IF EXISTS `sys_user_role`;
CREATE TABLE `sys_user_role` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `ROLE_ID` bigint(20) DEFAULT NULL COMMENT '角色ID',
  `USER_ID` bigint(20) DEFAULT NULL COMMENT '用户ID',
  `CREATED_BY` bigint(20) DEFAULT NULL COMMENT '创建人ID',
  `CREATE_TIME` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `UPDATED_BY` bigint(20) DEFAULT NULL COMMENT '修改人ID',
  `UPDATE_TIME` datetime DEFAULT NULL COMMENT '最后修改时间',
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=169 DEFAULT CHARSET=utf8 COMMENT='用户角色关联表';

-- ----------------------------
-- Records of sys_user_role
-- ----------------------------
INSERT INTO `sys_user_role` VALUES ('21', '15', '95', '95', '2015-01-19 11:03:04', null, null);
INSERT INTO `sys_user_role` VALUES ('22', '20', '95', '95', '2015-01-19 11:03:22', null, null);
INSERT INTO `sys_user_role` VALUES ('23', '21', '95', '95', '2015-01-19 11:03:22', null, null);
INSERT INTO `sys_user_role` VALUES ('24', '19', '95', '95', '2015-01-19 11:04:30', null, null);
INSERT INTO `sys_user_role` VALUES ('25', '18', '95', '95', '2015-01-19 11:05:17', null, null);
INSERT INTO `sys_user_role` VALUES ('26', '22', '95', '95', '2015-01-19 11:05:17', null, null);
INSERT INTO `sys_user_role` VALUES ('74', '12', '95', '105', '2015-01-27 09:56:45', null, null);
INSERT INTO `sys_user_role` VALUES ('75', '12', '95', '105', '2015-01-27 09:56:55', null, null);
INSERT INTO `sys_user_role` VALUES ('78', '43', '95', '105', '2015-01-27 10:12:38', null, null);
INSERT INTO `sys_user_role` VALUES ('79', '43', '95', '105', '2015-01-27 10:12:46', null, null);
