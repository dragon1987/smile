package com.smile.sharding.sqlSession;

import com.smile.sharding.loadbalance.IDBLoadBalance;
import org.apache.ibatis.cursor.Cursor;
import org.apache.ibatis.executor.BatchResult;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.session.ResultHandler;
import org.apache.ibatis.session.RowBounds;
import org.apache.ibatis.session.SqlSession;

import java.sql.Connection;
import java.util.List;
import java.util.Map;

/*
 * 组数据源管理，封装一主多从数据源，实现了SqlSession接口只是方便RW分离，底层仍是使用的DBSqlSessionTemplate实现
 */
public class GroupSqlSession implements SqlSession {

    /**
     * group sql的 唯一标识
     */
    private String identity;

    //是否开启读写分离功能，默认不开启
    private boolean isReadWriteSplit = false;

    /**
     * 主sql session 主要负责更新操作(包括,添加,修改,删除).单库时,也负责读
     */
    private SqlSessionUnit masterSqlSession;

    /**
     * 从sql session 主要负责读,一般用同步工具从主库同步,有延迟.
     */
    private List<SqlSessionUnit> slaveSqlSessions;

    /**
     * 主从sql session路由器,可以自定义,默认路由器
     */
    private IDBLoadBalance dbLoadBalance = null;

    public GroupSqlSession(SqlSessionUnit masterSqlSession, List<SqlSessionUnit> slaveSqlSessions, boolean readWriteSplit, IDBLoadBalance dbLoadBalance) {
        this.masterSqlSession = masterSqlSession;
        this.slaveSqlSessions = slaveSqlSessions;
        this.isReadWriteSplit = readWriteSplit;
        if (isReadWriteSplit && dbLoadBalance != null && slaveSqlSessions != null && slaveSqlSessions.size() > 0) {
            dbLoadBalance.initSqlSession(masterSqlSession, slaveSqlSessions);
        }
    }

    private SqlSession getSqlSession(SqlSessionUnit sqlSessionUnit) {
        if (SqlSessionHolder.isBatchExecuter()) {
            return sqlSessionUnit.getBatchSqlSessions();
        } else {
            return sqlSessionUnit.getSimpleSqlSession();
        }
    }

    private SqlSessionUnit selectSlaveSqlSession() {
        if (dbLoadBalance != null) {
            return dbLoadBalance.select();
        }
        return masterSqlSession;
    }

    public SqlSessionUnit getMasterSqlSession() {
        return masterSqlSession;
    }

    public void setMasterSqlSession(SqlSessionUnit masterSqlSession) {
        this.masterSqlSession = masterSqlSession;
    }

    public List<SqlSessionUnit> getSlaveSqlSessions() {
        return slaveSqlSessions;
    }

    public void setSlaveSqlSessions(List<SqlSessionUnit> slaveSqlSessions) {
        this.slaveSqlSessions = slaveSqlSessions;
    }

    public String getIdentity() {
        return identity;
    }

    public void setIdentity(String identity) {
        this.identity = identity;
    }

    @Override
    public int delete(String statement) {
        return getSqlSession(masterSqlSession).delete(statement);
    }

    @Override
    public int delete(String statement, Object parameter) {
        return getSqlSession(masterSqlSession).delete(statement, parameter);
    }

    @Override
    public int insert(String statement) {
        return getSqlSession(masterSqlSession).insert(statement);
    }

    @Override
    public int insert(String statement, Object parameter) {
        return getSqlSession(masterSqlSession).insert(statement, parameter);
    }

    @Override
    public int update(String statement) {
        return getSqlSession(masterSqlSession).update(statement);
    }

    @Override
    public int update(String statement, Object parameter) {
        return getSqlSession(masterSqlSession).update(statement, parameter);
    }

    @Override
    public void select(String arg0, ResultHandler arg1) {
        getSqlSession(selectSlaveSqlSession()).select(arg0, null, null, arg1);
    }

    @Override
    public void select(String arg0, Object arg1, ResultHandler arg2) {
        getSqlSession(selectSlaveSqlSession()).select(arg0, arg1, null, arg2);
    }

    @Override
    public void select(String arg0, Object arg1, RowBounds arg2, ResultHandler arg3) {
        getSqlSession(selectSlaveSqlSession()).select(arg0, arg1, arg2, arg3);
    }

    @Override
    public <E> List<E> selectList(String statement) {
        return getSqlSession(selectSlaveSqlSession()).selectList(statement);
    }

    @Override
    public <E> List<E> selectList(String statement, Object parameter) {
        return getSqlSession(selectSlaveSqlSession()).selectList(statement, parameter);
    }

    @Override
    public <E> List<E> selectList(String statement, Object parameter, RowBounds rowBounds) {
        return getSqlSession(selectSlaveSqlSession()).selectList(statement, parameter, rowBounds);
    }

    @Override
    public <K, V> Map<K, V> selectMap(String statement, String mapKey) {
        return getSqlSession(selectSlaveSqlSession()).selectMap(statement, mapKey);
    }

    @Override
    public <K, V> Map<K, V> selectMap(String statement, Object parameter, String mapKey) {
        return getSqlSession(selectSlaveSqlSession()).selectMap(statement, parameter, mapKey);
    }

    @Override
    public <K, V> Map<K, V> selectMap(String statement, Object parameter, String mapKey, RowBounds rowBounds) {
        return getSqlSession(selectSlaveSqlSession()).selectMap(statement, parameter, mapKey, rowBounds);
    }

    @Override
    public <T> Cursor<T> selectCursor(String s) {
        return null;
    }

    @Override
    public <T> Cursor<T> selectCursor(String s, Object o) {
        return null;
    }

    @Override
    public <T> Cursor<T> selectCursor(String s, Object o, RowBounds rowBounds) {
        return null;
    }

    @SuppressWarnings("unchecked")
    @Override
    public <T> T selectOne(String statement) {
        return (T) getSqlSession(selectSlaveSqlSession()).selectOne(statement);
    }

    @SuppressWarnings("unchecked")
    @Override
    public <T> T selectOne(String statement, Object parameter) {
        return (T) getSqlSession(selectSlaveSqlSession()).selectOne(statement, parameter);
    }

    @Override
    public void commit() {
        throw new UnsupportedOperationException("Manual commit is not allowed over a Spring managed SqlSession");
    }

    @Override
    public void commit(boolean force) {
        throw new UnsupportedOperationException("Manual commit is not allowed over a Spring managed SqlSession");
    }

    @Override
    public void rollback() {
        throw new UnsupportedOperationException("Manual rollback is not allowed over a Spring managed SqlSession");
    }

    @Override
    public void rollback(boolean force) {
        throw new UnsupportedOperationException("Manual rollback is not allowed over a Spring managed SqlSession");
    }

    @Override
    public List<BatchResult> flushStatements() {
        throw new UnsupportedOperationException("Manual flushStatements is not allowed over a Spring managed SqlSession");
    }

    @Override
    public void close() {
        throw new UnsupportedOperationException("Manual close is not allowed over a Spring managed SqlSession");
    }

    @Override
    public void clearCache() {
        throw new UnsupportedOperationException("Manual clearCache is not allowed over a Spring managed SqlSession");
    }

    @Override
    public Configuration getConfiguration() {
        return masterSqlSession.getSimpleSqlSession().getConfiguration();
    }

    @Override
    public <T> T getMapper(Class<T> type) {
        return masterSqlSession.getSimpleSqlSession().getMapper(type);
    }

    @Override
    public Connection getConnection() {
        throw new UnsupportedOperationException("Manual getConnection is not allowed over a Spring managed SqlSession");
    }
}
