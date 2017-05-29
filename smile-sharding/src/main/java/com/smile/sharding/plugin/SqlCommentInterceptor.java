package com.smile.sharding.plugin;

import com.smile.sharding.page.SqlUtil;
import org.apache.ibatis.executor.statement.StatementHandler;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.mapping.SqlCommandType;
import org.apache.ibatis.plugin.*;
import org.apache.ibatis.reflection.MetaObject;

import java.sql.Connection;
import java.util.Properties;

/**
 * 在select语句前面加上mybatis statementId，方便调试
 * <p/>
 * <pre>
 *
 * @author hudi
 *         <p/>
 *         <p/>
 *         创建日期: 2014-5-16
 *         修改人 :
 *         修改说明:
 *         评审人 ：
 *         </pre>
 */
@Intercepts({ @Signature(type = StatementHandler.class, method = "prepare", args = { Connection.class }) })
public class SqlCommentInterceptor implements Interceptor {
    @Override
    public Object intercept(Invocation invocation) throws Throwable {
        StatementHandler statementHandler = (StatementHandler) invocation.getTarget();
        MetaObject metaStatementHandler = SqlUtil.forObject(statementHandler);
        MappedStatement mappedStatement = (MappedStatement) SqlUtil.forObject(statementHandler.getParameterHandler()).getValue("mappedStatement");
        String sql = statementHandler.getBoundSql().getSql().trim();
        // 只在select前面加上注释
        if (mappedStatement.getSqlCommandType().equals(SqlCommandType.SELECT)) {
            sql = "/* " + mappedStatement.getId() + " */" + sql;
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
