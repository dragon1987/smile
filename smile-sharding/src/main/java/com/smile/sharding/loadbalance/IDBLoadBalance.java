/*
 * @(#)LoadBalance.java 2013-4-25
 * 
 * Copy Right@ 纽海信息技术有限公司
 */

package com.smile.sharding.loadbalance;

import com.smile.sharding.sqlSession.SqlSessionUnit;

import java.util.List;

/**
 * 主从 选择器
 * 
 * <pre>
 * @author zhutao
 *
 *
 * 创建日期: 2013-6-17
 * 修改人 :  
 * 修改说明: 
 * 评审人 ：
 * </pre>
 */
public interface IDBLoadBalance {
    void initSqlSession(SqlSessionUnit masterSqlSession, List<SqlSessionUnit> sqlSessions);

    /**
     * 根据负载均衡策略，选择一个可用的服务<br/>
     * 会并发调用
     */
    SqlSessionUnit select();
}
