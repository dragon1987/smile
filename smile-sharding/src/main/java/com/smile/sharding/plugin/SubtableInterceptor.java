package com.smile.sharding.plugin;


import com.smile.sharding.page.SqlUtil;
import org.apache.commons.lang3.StringUtils;
import org.apache.ibatis.executor.statement.StatementHandler;
import org.apache.ibatis.mapping.BoundSql;
import org.apache.ibatis.plugin.*;
import org.apache.ibatis.reflection.MetaObject;

import java.sql.Connection;
import java.util.Properties;

@Intercepts({ @Signature(type = StatementHandler.class, method = "prepare", args = { Connection.class }) })
public class SubtableInterceptor implements Interceptor {
    @Override
    public Object intercept(Invocation invocation) throws Throwable {
        StatementHandler statementHandler = (StatementHandler) invocation.getTarget();
        MetaObject metaStatementHandler = SqlUtil.forObject(statementHandler);
        BoundSql boundSql = (BoundSql) metaStatementHandler.getValue("boundSql");
        String sql = boundSql.getSql();
        Object paramObj = boundSql.getParameterObject();
        sql = SubtableUtil.getSubtabledSql(sql, paramObj);
        if (StringUtils.isNotBlank(sql)) {
            metaStatementHandler.setValue("boundSql.sql", sql);
        }
        return invocation.proceed();
    }

    @Override
    public Object plugin(Object target) {
        return Plugin.wrap(target, this);
    }

    @Override
    public void setProperties(Properties properties) {

    }

}
