package com.smile.sharding.plugin;

import com.smile.sharding.page.SqlUtil;
import com.smile.sharding.sqlParser.ShardingExpressionVisitor;
import com.smile.sharding.sqlSession.SqlSessionHolder;
import net.sf.jsqlparser.parser.CCJSqlParserManager;
import net.sf.jsqlparser.statement.Statement;
import org.apache.commons.lang3.StringUtils;
import org.apache.ibatis.executor.statement.StatementHandler;
import org.apache.ibatis.mapping.BoundSql;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.plugin.*;
import org.apache.ibatis.reflection.MetaObject;

import java.io.StringReader;
import java.sql.Connection;
import java.util.Properties;

/**
 * 识别特殊函数的拦截器
 */
@Intercepts({@Signature(type = StatementHandler.class, method = "prepare", args = {Connection.class})})
public class FunctionInterceptor implements Interceptor {

    @Override
    public Object intercept(Invocation invocation) throws Throwable {
        StatementHandler statementHandler = (StatementHandler) invocation.getTarget();
        MetaObject metaStatementHandler = SqlUtil.forObject(statementHandler);
        BoundSql boundSql = (BoundSql) metaStatementHandler.getValue("boundSql");
        String sql = boundSql.getSql();
        if (StringUtils.isNotBlank(sql) && SqlSessionHolder.isSharding()) {
            MappedStatement mappedStatement = (MappedStatement) SqlUtil.forObject(statementHandler.getParameterHandler()).getValue("mappedStatement");
            Statement statement = new CCJSqlParserManager().parse(new StringReader(sql));
            statement.accept(new ShardingExpressionVisitor(mappedStatement));
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
