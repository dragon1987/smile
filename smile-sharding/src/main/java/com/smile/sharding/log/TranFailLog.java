package com.smile.sharding.log;

import com.alibaba.fastjson.JSON;

public class TranFailLog {

    /**
     * 数据源
     */
    private String datasourceId;

    /**
     * SQL Statement
     */
    private String sqlStatement;

    /**
     * 异常原因
     */
    private String exceptionCause;

    private Object[] param;

    public String getDatasourceId() {
        return datasourceId;
    }

    public void setDatasourceId(String datasourceId) {
        this.datasourceId = datasourceId;
    }

    public String getSqlStatement() {
        return sqlStatement;
    }

    public void setSqlStatement(String sqlStatement) {
        this.sqlStatement = sqlStatement;
    }

    public String getExceptionCause() {
        return exceptionCause;
    }

    public void setExceptionCause(String exceptionCause) {
        this.exceptionCause = exceptionCause;
    }

    public Object[] getParam() {
        return param;
    }

    public void setParam(Object[] param) {
        this.param = param;
    }

    @Override
    public String toString() {
        try {
            return String.format("{\"ds\":\"%s\",\"ss\":\"%s\",\"sp\":\"%s\",\"ec\":\"%s\"},", datasourceId, sqlStatement, JSON.toJSONString(param), exceptionCause);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
