/*
 * @(#)PollLoadBalance.java 2013-4-26
 * 
 * Copy Right@ 纽海信息技术有限公司
 */

package com.smile.sharding.loadbalance;

import com.smile.sharding.sqlSession.SqlSessionUnit;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 主从轮询选择
 */
public class PollLoadBalance implements IDBLoadBalance {

    protected final Log logger = LogFactory.getLog(PollLoadBalance.class);

    protected SqlSessionUnit masterSqlSessionUnit;

    protected List<SqlSessionUnit> sqlSessions = new ArrayList<SqlSessionUnit>();

    private AtomicInteger index = new AtomicInteger(0);

    @Override
    public void initSqlSession(SqlSessionUnit masterSqlSession,List<SqlSessionUnit> sqlSessions) {
        this.masterSqlSessionUnit=masterSqlSession;
        this.sqlSessions = sqlSessions;
    }

    @Override
    public SqlSessionUnit select() {
        return sqlSessions.get(incrementAndGetWithin(sqlSessions.size()));
    }

    protected int incrementAndGetWithin(int maxSize) {
        for (;;) {
            int current = index.get();
            int next = current + 1;
            if (next >= maxSize) {
                next = 0;
            }
            if (index.compareAndSet(current, next)) {
                return next;
            }
        }
    }
}
