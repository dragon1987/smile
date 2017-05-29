package com.smile.sharding.sqlSession;

import org.apache.ibatis.session.SqlSession;

/**
 * sql session 单元,主要是 simple和batch两种不同的模式
 * Created by zhutao on 2014/11/20.
 */
public class SqlSessionUnit {

    /**
     * simple 模式的sql session
     */
    private SqlSession simpleSqlSession;

    /**
     * 批处理 模式的sql session
     */
    private SqlSession batchSqlSessions;

    public SqlSession getSimpleSqlSession() {
        return simpleSqlSession;
    }

    public void setSimpleSqlSession(SqlSession simpleSqlSession) {
        this.simpleSqlSession = simpleSqlSession;
    }

    public SqlSession getBatchSqlSessions() {
        return batchSqlSessions;
    }

    public void setBatchSqlSessions(SqlSession batchSqlSessions) {
        this.batchSqlSessions = batchSqlSessions;
    }
}
