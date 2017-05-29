package com.smile.sharding.execution;

import com.smile.sharding.enums.StatementType;
import org.apache.ibatis.session.ExecutorType;
import org.apache.ibatis.session.ResultHandler;
import org.apache.ibatis.session.RowBounds;
import org.apache.ibatis.session.SqlSession;

import java.util.concurrent.ExecutorService;


public class ConcurrentRequest {

	private StatementType crud;

	private String statement;

	private Object parameter;

	private String mapKey;

	private ExecutorService executor;

	private ExecutorType executorType = ExecutorType.SIMPLE;

	private RowBounds rowBounds = null;//RowBounds.DEFAULT;

	private String dataSourceName;

	private SqlSession sqlSession;

    private ResultHandler resultHandler;

	public SqlSession getSqlSession() {
		return sqlSession;
	}

	public void setSqlSession(SqlSession sqlSession) {
		this.sqlSession = sqlSession;
	}

	public String getDataSourceName() {
		return dataSourceName;
	}

	public void setDataSourceName(String dataSourceName) {
		this.dataSourceName = dataSourceName;
	}

	public StatementType getCrud() {
		return crud;
	}

	public void setCrud(StatementType crud) {
		this.crud = crud;
	}

	public String getStatement() {
		return statement;
	}

	public void setStatement(String statement) {
		this.statement = statement;
	}

	public Object getParameter() {
		return parameter;
	}

	public void setParameter(Object parameter) {
		this.parameter = parameter;
	}

	public String getMapKey() {
		return mapKey;
	}

	public void setMapKey(String mapKey) {
		this.mapKey = mapKey;
	}

	public ExecutorService getExecutor() {
		return executor;
	}

	public void setExecutor(ExecutorService executor) {
		this.executor = executor;
	}

	public ExecutorType getExecutorType() {
		return executorType;
	}

	public void setExecutorType(ExecutorType executorType) {
		this.executorType = executorType;
	}

	public RowBounds getRowBounds() {
		return rowBounds;
	}

	public void setRowBounds(RowBounds rowBounds) {
		this.rowBounds = rowBounds;
	}

    public ResultHandler getResultHandler() {
        return resultHandler;
    }

    public void setResultHandler(ResultHandler resultHandler) {
        this.resultHandler = resultHandler;
    }
}
