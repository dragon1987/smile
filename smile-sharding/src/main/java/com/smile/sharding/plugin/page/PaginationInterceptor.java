/**
 * Copyright &copy; 2012-2014 <a href="https://github.com/thinkgem/jeesite">JeeSite</a> All rights reserved.
 */
package com.smile.sharding.plugin.page;


import com.smile.sharding.page.Pagination;
import com.smile.sharding.plugin.page.dialect.Dialect;
import com.smile.sharding.utils.Reflections;
import com.smile.sharding.plugin.page.dialect.db.*;
import org.apache.commons.lang3.StringUtils;
import org.apache.ibatis.executor.Executor;
import org.apache.ibatis.logging.Log;
import org.apache.ibatis.logging.LogFactory;
import org.apache.ibatis.mapping.BoundSql;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.mapping.SqlSource;
import org.apache.ibatis.plugin.*;
import org.apache.ibatis.reflection.MetaObject;
import org.apache.ibatis.session.ResultHandler;
import org.apache.ibatis.session.RowBounds;

import java.io.Serializable;
import java.sql.Connection;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * 数据库分页插件，只拦截查询语句.
 *
 * @author poplar.yfyang / thinkgem
 * @version 2013-8-28
 */
@Intercepts({@Signature(type = Executor.class, method = "query",
        args = {MappedStatement.class, Object.class, RowBounds.class, ResultHandler.class})})
public class PaginationInterceptor implements Interceptor, Serializable {


    private static final long serialVersionUID = 1L;

    protected static final String PAGE = "page";

    protected static final String DELEGATE = "delegate";

    protected static final String MAPPED_STATEMENT = "mappedStatement";

    protected Log log = LogFactory.getLog(this.getClass());

    @Override
    public Object intercept(Invocation invocation) throws Throwable {

        final Object[] args = invocation.getArgs();
        MappedStatement ms = (MappedStatement) args[0];
        Object parameterObject = args[1];
        //分页信息
        Pagination pagination = null;
        if ((parameterObject instanceof HashMap) && ((HashMap) parameterObject).containsKey("page")) {
            pagination = (Pagination) ((Map) parameterObject).get("page");
            if (((Map) parameterObject).size() == 2) {
                for (Object object : ((Map) parameterObject).values()) {
                    if (!(object instanceof Pagination)) {
                        parameterObject = object;
                        args[1] = parameterObject;
                    }
                }
            }
        } else {
            return invocation.proceed();
        }
        BoundSql boundSql = ms.getBoundSql(parameterObject);


        //如果设置了分页对象，则进行分页
        if (pagination != null) {

            if (StringUtils.isBlank(boundSql.getSql())) {
                return null;
            }
            String originalSql = boundSql.getSql().trim();

            Connection conn = ms.getConfiguration().getEnvironment().getDataSource().getConnection();
            String driverName = conn.getMetaData().getDriverName();
            //得到总记录数
            pagination.setTotal(SQLHelper.getCount(originalSql, driverName, conn, ms, parameterObject, boundSql, log));
            Dialect dialect = getDialect(driverName);
            //分页查询 本地化对象 修改数据库注意修改实现
            String pageSql = SQLHelper.generatePageSql(originalSql, pagination, dialect);
            invocation.getArgs()[2] = new RowBounds(RowBounds.NO_ROW_OFFSET, RowBounds.NO_ROW_LIMIT);
            BoundSql newBoundSql = new BoundSql(ms.getConfiguration(), pageSql, boundSql.getParameterMappings(), boundSql.getParameterObject());
            //解决MyBatis 分页foreach 参数失效 start
            if (Reflections.getFieldValue(boundSql, "metaParameters") != null) {
                MetaObject mo = (MetaObject) Reflections.getFieldValue(boundSql, "metaParameters");
                Reflections.setFieldValue(newBoundSql, "metaParameters", mo);
            }
            //解决MyBatis 分页foreach 参数失效 end
            MappedStatement newMs = copyFromMappedStatement(ms, new BoundSqlSqlSource(newBoundSql));
            invocation.getArgs()[0] = newMs;
        }
//        }
        return invocation.proceed();
    }


    @Override
    public Object plugin(Object target) {
        return Plugin.wrap(target, this);
    }

    @Override
    public void setProperties(Properties properties) {

    }

    /**
     * 设置属性，支持自定义方言类和制定数据库的方式
     * <code>dialectClass</code>,自定义方言类。可以不配置这项
     * <ode>dbms</ode> 数据库类型，插件支持的数据库
     * <code>sqlPattern</code> 需要拦截的SQL ID
     *
     * @param driverName 属性
     */
    protected Dialect getDialect(String driverName) {
        driverName = driverName.toLowerCase();
        if (driverName.indexOf("db2") > -1) {
            return new DB2Dialect();
        } else if (driverName.indexOf("derby") > -1) {
            return new DerbyDialect();
        } else if (driverName.indexOf("h2") > -1) {
            return new H2Dialect();
        } else if (driverName.indexOf("hsql") > -1) {
            return new HSQLDialect();
        } else if (driverName.indexOf("mysql") > -1) {
            return new MySQLDialect();
        } else if (driverName.indexOf("oracle") > -1) {
            return new OracleDialect();
        } else if (driverName.indexOf("postgre") > -1) {
            return new PostgreSQLDialect();
        } else if (driverName.indexOf("mssql") > -1 || driverName.indexOf("sqlserver") > -1) {
            return new SQLServer2005Dialect();
        } else if (driverName.indexOf("sybase") > -1) {
            return new SybaseDialect();
        } else {
            throw new RuntimeException("mybatis dialect error.");
        }
    }

    private MappedStatement copyFromMappedStatement(MappedStatement ms,
                                                    SqlSource newSqlSource) {
        MappedStatement.Builder builder = new MappedStatement.Builder(ms.getConfiguration(),
                ms.getId(), newSqlSource, ms.getSqlCommandType());
        builder.resource(ms.getResource());
        builder.fetchSize(ms.getFetchSize());
        builder.statementType(ms.getStatementType());
        builder.keyGenerator(ms.getKeyGenerator());
        if (ms.getKeyProperties() != null) {
            for (String keyProperty : ms.getKeyProperties()) {
                builder.keyProperty(keyProperty);
            }
        }
        builder.timeout(ms.getTimeout());
        builder.parameterMap(ms.getParameterMap());
        builder.resultMaps(ms.getResultMaps());
        builder.cache(ms.getCache());
        return builder.build();
    }

    public static class BoundSqlSqlSource implements SqlSource {
        BoundSql boundSql;

        public BoundSqlSqlSource(BoundSql boundSql) {
            this.boundSql = boundSql;
        }

        public BoundSql getBoundSql(Object parameterObject) {
            return boundSql;
        }
    }
}
