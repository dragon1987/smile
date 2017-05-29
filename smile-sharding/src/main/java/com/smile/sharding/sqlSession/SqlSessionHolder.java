package com.smile.sharding.sqlSession;

import com.smile.sharding.enums.SqlExpressionType;
import com.smile.sharding.sqlParser.OrderBy;
import org.apache.commons.lang3.StringUtils;
import org.apache.ibatis.mapping.ResultMap;
import org.apache.ibatis.mapping.ResultMapping;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * sql session的相关变量
 * Created by zhutao on 2014/11/20.
 */
public class SqlSessionHolder {

    private final static Map<String, String> columnToPropertyMap = new ConcurrentHashMap<String, String>();

    private static ThreadLocal<Boolean> batchExecuters = new InheritableThreadLocal<Boolean>();

    private static Map<String, SqlExpressionType> expressions = new ConcurrentHashMap<String, SqlExpressionType>();

    private static ThreadLocal<Boolean> shardings = new InheritableThreadLocal<Boolean>();

    private static Map<String, List<OrderBy>> orderBies = new ConcurrentHashMap<String, List<OrderBy>>();

    public static void setOrderBy(String sql, List<OrderBy> orderbies) {
        orderBies.put(sql, orderbies);
    }

    public static List<OrderBy> getOrderBy(String sql) {
        return orderBies.get(sql);
    }

    public static void clearOrderBy(String sql) {
        orderBies.remove(sql);
    }

    public static void setBatchExecuter() {
        batchExecuters.set(true);
    }

    public static boolean isBatchExecuter() {
        if (batchExecuters.get() == null) {
            return false;
        }
        return batchExecuters.get();
    }

    public static void clearBatchExecuter() {
        batchExecuters.remove();
    }

    public static void setSharding() {
        shardings.set(true);
    }

    public static boolean isSharding() {
        if (shardings.get() == null) {
            return false;
        }
        return shardings.get();
    }

    public static void clearSharding() {
        shardings.remove();
    }

    public static void setSqlExpressionType(String sql, SqlExpressionType sqlExpressionType) {
        expressions.put(sql, sqlExpressionType);
    }

    public static SqlExpressionType getSqlExpressionType(String sql) {
        return expressions.get(sql);
    }

    private static void buildMapper(String mapperId, List<ResultMap> resultMaps) {
        for (ResultMap resultMap : resultMaps) {
            for (ResultMapping resultMapping : resultMap.getIdResultMappings()) {
                columnToPropertyMap.put(mapperId + "_" + resultMapping.getColumn(), resultMapping.getProperty());
            }
            for (ResultMapping resultMapping : resultMap.getConstructorResultMappings()) {
                columnToPropertyMap.put(mapperId + "_" + resultMapping.getColumn(), resultMapping.getProperty());
            }
            for (ResultMapping resultMapping : resultMap.getPropertyResultMappings()) {
                columnToPropertyMap.put(mapperId + "_" + resultMapping.getColumn(), resultMapping.getProperty());
            }
            for (ResultMapping resultMapping : resultMap.getResultMappings()) {
                columnToPropertyMap.put(mapperId + "_" + resultMapping.getColumn(), resultMapping.getProperty());
            }
        }
    }

    public static String getProperty(String mapperId, String column, List<ResultMap> resultMap) {
        if (StringUtils.isEmpty(columnToPropertyMap.get(mapperId + "_" + column))) {
            buildMapper(mapperId, resultMap);
        }
        return columnToPropertyMap.get(mapperId + "_" + column) == null ? column : columnToPropertyMap.get(mapperId + "_" + column);
    }

}
