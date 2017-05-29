package com.smile.sharding.plugin;

import com.smile.sharding.page.SqlUtil;
import com.smile.sharding.sqlSession.SqlSessionHolder;
import com.smile.sharding.page.Pagination;
import org.apache.commons.lang3.StringUtils;
import org.apache.ibatis.executor.Executor;
import org.apache.ibatis.mapping.BoundSql;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.plugin.*;
import org.apache.ibatis.session.ResultHandler;
import org.apache.ibatis.session.RowBounds;

import java.lang.reflect.InvocationTargetException;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.*;

@SuppressWarnings({"rawtypes", "unchecked"})
@Intercepts(@Signature(type = Executor.class, method = "query", args = {MappedStatement.class, Object.class, RowBounds.class, ResultHandler.class}))
public class PaginationInterceptor implements Interceptor {

    private final static String ORACLE_DRIVER_NAME = "Oracle JDBC driver";

    //数据库方言
    private final static SqlUtil mysqlUtil = new SqlUtil("mysql");

    private final static SqlUtil oracleUtil = new SqlUtil("oracle");

    /**
     * 分页最大可取数目
     */
    private final static int MAX_LIMIT = 5000;

    private int limit = MAX_LIMIT;

    /**
     * Mybatis拦截器方法
     *
     * @param invocation 拦截器入参
     * @return 返回执行结果
     * @throws Throwable 抛出异常
     */
    public Object intercept(Invocation invocation) throws Throwable {
        final Object[] args = invocation.getArgs();
        MappedStatement ms = (MappedStatement) args[0];
        Object parameterObject = args[1];
        //分页信息
        Pagination pagination = null;

        if ((parameterObject instanceof HashMap)) {
            for (Object entity : ((HashMap) parameterObject).entrySet()) {
                if (((Map.Entry) entity).getValue() instanceof Pagination) {
                    pagination = (Pagination) ((Map.Entry) entity).getValue();
                }
            }
        }
        if (pagination == null) {
            return invocation.proceed();
        }
        //简单的通过total的值来判断是否进行count查询
        SqlUtil sqlUtil = getSqlUtils(ms);
        int result = getCount(invocation, args, ms, args[1], sqlUtil, pagination);
        //pageSize>0的时候执行分页查询，pageSize<=0的时候不执行相当于可能只返回了一个count
        if (result > 0) {
            //分库的时候，需要把每个库的数据相加
            pagination.setTotal(result + pagination.getTotal());
            return getResults(invocation, args, ms, args[1], pagination, sqlUtil);
        } else {
            List rows = new ArrayList();
            pagination.setRows(rows);
            return rows;
        }
    }

    private Object getResults(Invocation invocation, Object[] args, MappedStatement ms, Object parameterObject, Pagination pagination, SqlUtil sqlUtil) throws InvocationTargetException, IllegalAccessException {
        BoundSql boundSql = null;
        //只有静态sql需要获取boundSql
        if (!sqlUtil.isDynamic(ms)) {
            boundSql = ms.getBoundSql(parameterObject);
        }
        //将参数中的MappedStatement替换为新的qs
        args[0] = sqlUtil.getPageMappedStatement(ms, boundSql, pagination);
        //动态sql时，boundSql在这儿通过新的ms获取
        if (boundSql == null) {
            boundSql = ((MappedStatement) args[0]).getBoundSql(parameterObject);
        }
        //判断parameterObject，然后赋值
        if (SqlSessionHolder.isSharding()) {
            Pagination shardingPagination = new Pagination();
            shardingPagination.setOffset(0);
            shardingPagination.setLimit(limit);
            args[1] = sqlUtil.setPageParameter((MappedStatement) args[0], parameterObject, boundSql, shardingPagination);
            //执行分页查询
            Object result = invocation.proceed();
            //得到处理结果
            pagination.setRows((List) result);
            return result;
        } else {
            args[1] = sqlUtil.setPageParameter((MappedStatement) args[0], parameterObject, boundSql, pagination);
            //执行分页查询
            Object result = invocation.proceed();
            //得到处理结果
            pagination.setRows((List) result);
            return result;
        }
    }

    private int getCount(Invocation invocation, Object[] args, MappedStatement ms, Object parameterObject, SqlUtil sqlUtil, Pagination pagination) throws InvocationTargetException, IllegalAccessException {
        Object result;
        BoundSql boundSql = null;
        //只有静态sql需要获取boundSql
        if (!sqlUtil.isDynamic(ms)) {
            boundSql = ms.getBoundSql(parameterObject);
        }
        //将参数中的MappedStatement替换为新的qs
        args[0] = sqlUtil.getCountMappedStatement(ms, boundSql, pagination);
        //查询总数
        result = invocation.proceed();
        return (Integer) ((List) result).get(0);
    }


    private SqlUtil getSqlUtils(MappedStatement ms) throws SQLException {
        Connection connection = ms.getConfiguration().getEnvironment().getDataSource().getConnection();
        try {
            SqlUtil sqlUtil;

            if (ORACLE_DRIVER_NAME.equals(connection.getMetaData().getDriverName())) {
                sqlUtil = oracleUtil;
            } else {
                sqlUtil = mysqlUtil;
            }
            return sqlUtil;
        } finally {
            connection.close();
        }
    }


    /**
     * 只拦截Executor
     *
     * @param target
     * @return
     */
    public Object plugin(Object target) {
        if (target instanceof Executor) {
            return Plugin.wrap(target, this);
        } else {
            return target;
        }
    }

    /**
     * 设置属性值
     *
     * @param p 属性值
     */
    public void setProperties(Properties p) {
        String limitString = p.getProperty("limit");
        if (StringUtils.isNotEmpty(limitString) && Integer.valueOf(limitString) < MAX_LIMIT) {
            limit = Integer.valueOf(limitString);
        }
    }
}