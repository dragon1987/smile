package com.smile.sharding.sqlSession;

import com.alibaba.fastjson.JSON;
import com.smile.sharding.datasources.DataSourceDescriptor;
import com.smile.sharding.enums.SqlExpressionType;
import com.smile.sharding.enums.StatementType;
import com.smile.sharding.execution.DefaultConcurrentRequestProcessor;
import com.smile.sharding.execution.IConcurrentRequestProcessor;
import com.smile.sharding.datasources.IDataSourceService;
import com.smile.sharding.execution.ConcurrentRequest;
import com.smile.sharding.page.Pagination;
import org.apache.ibatis.cursor.Cursor;
import org.apache.ibatis.executor.BatchResult;
import org.apache.ibatis.session.*;
import org.apache.log4j.Logger;
import org.mybatis.spring.SqlSessionFactoryBean;
import org.mybatis.spring.SqlSessionTemplate;
import org.mybatis.spring.transaction.SpringManagedTransactionFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.io.Resource;
import org.springframework.dao.IncorrectResultSizeDataAccessException;

import javax.sql.DataSource;
import java.sql.Connection;
import java.util.*;
import java.util.concurrent.*;

public class DBSqlSessionTemplate implements SqlSession, InitializingBean, DisposableBean {

    private static Logger logger = Logger.getLogger(DBSqlSessionTemplate.class);

    private IDataSourceService dataSourceService;

    // qing, sql执行时间阀值，默认超过2秒，就写日志,设为<1不记
    private int sqlExecTimeThreshold = 2000;

    // qing,select返回行数阀值，默认超过5000条，就写日志,设为<1不记
    private long sqlSelectCountThreshold = 5000;

    /**
     * 分库时是否多线程执行查询操作
     */
    private boolean mutiThreadExcuteSelect = true;

    private Resource[] mapperLocations;

    private String typeAliasesPackage;

    /**
     * 每个数据源上设立一个 ExecutorService  key是数据源identity,value是ExecutorService
     * 目前针对一个group数据源共设立一个的线程池
     */
    private Map<String, ExecutorService> dataSourceExecutors = new HashMap<String, ExecutorService>();

    private IConcurrentRequestProcessor concurrentRequestProcessor;

    private Map<String, SqlSession> sessionMap = new HashMap<String, SqlSession>();

    private Resource configLocation;


    public String getTypeAliasesPackage() {
        return typeAliasesPackage;
    }

    public void setTypeAliasesPackage(String typeAliasesPackage) {
        this.typeAliasesPackage = typeAliasesPackage;
    }

    public Resource[] getMapperLocations() {
        return mapperLocations;
    }

    public void setMapperLocations(Resource[] mapperLocations) {
        this.mapperLocations = mapperLocations;
    }


    public DBSqlSessionTemplate(IDataSourceService service) {
        this.dataSourceService = service;
    }

    public IDataSourceService getDataSourceService() {
        return this.dataSourceService;
    }

    public void setConfigLocation(Resource configLocation) {
        this.configLocation = configLocation;
    }

    public void setSqlExecTimeThreshold(int sqlExecTimeThreshold) {
        this.sqlExecTimeThreshold = sqlExecTimeThreshold;
    }


    public void setSqlSelectCountThreshold(long sqlSelectCountThreshold) {
        this.sqlSelectCountThreshold = sqlSelectCountThreshold;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        if ((this.getDataSourceService() == null)) {
            throw new RuntimeException("dataSourceService can't null");
        }
        try {
            concurrentRequestProcessor = new DefaultConcurrentRequestProcessor();
            // 为每一个数据源定义sql session template和spring的事务管理器
            // qing:该类为单例能节约内存资源
            Set<DataSourceDescriptor> dataSourceDescriptors = getDataSourceService().getDataSourceDescriptors();
            for (DataSourceDescriptor dataSourceDescriptor : dataSourceDescriptors) {
                this.sessionMap.put(dataSourceDescriptor.getIdentity(), buildGroupSqlSessionTemplate(dataSourceDescriptor));
                ExecutorService executor = createCustomExecutorService(dataSourceDescriptor.getThreadPoolSize(), "executor " + dataSourceDescriptor.getIdentity() + " datasourse");
                this.dataSourceExecutors.put(dataSourceDescriptor.getIdentity(), executor);
            }
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw e;
        }
    }

    /*
     * 构建group数据源，目前m,s都纳入了事务范围
     */
    private GroupSqlSession buildGroupSqlSessionTemplate(DataSourceDescriptor dataSourceDescriptor) throws Exception {
        SqlSessionUnit masterSqlSession = buildSqlSession(dataSourceDescriptor.getMasterDataSource());
        List<SqlSessionUnit> slaveSqlSessions = new ArrayList<SqlSessionUnit>();
        if (dataSourceDescriptor.getSlaveDataSources() != null) {
            for (DataSource dataSource : dataSourceDescriptor.getSlaveDataSources()) {
                slaveSqlSessions.add(buildSqlSession(dataSource));
            }
        }
        GroupSqlSession groupSqlSession = new GroupSqlSession(masterSqlSession, slaveSqlSessions, dataSourceDescriptor.isReadWriteSplit(), dataSourceDescriptor.getDbLoadBalance());
        return groupSqlSession;
    }

    private SqlSessionUnit buildSqlSession(DataSource dataSource) throws Exception {
        try {
            SqlSessionUnit sqlSessionUnit = new SqlSessionUnit();
            //simple 模式
            SqlSessionFactoryBean simpleSqlSessionFactoryBean = new SqlSessionFactoryBean();
            simpleSqlSessionFactoryBean.setDataSource(dataSource);
            simpleSqlSessionFactoryBean.setConfigLocation(this.configLocation);
            // qing:3.0.6版本为new SpringManagedTransactionFactory(ds)，3.1.1去掉了datasource参数
            SpringManagedTransactionFactory simpleTransactionFactory = new SpringManagedTransactionFactory();
            simpleSqlSessionFactoryBean.setTransactionFactory(simpleTransactionFactory);
            simpleSqlSessionFactoryBean.setMapperLocations(mapperLocations);
            simpleSqlSessionFactoryBean.setTypeAliasesPackage(typeAliasesPackage);
            SqlSessionFactory simpleSessionFacotry = simpleSqlSessionFactoryBean.getObject();
            SqlSessionTemplate simpleSqlSessionTemplate = new SqlSessionTemplate(simpleSessionFacotry);
            simpleSqlSessionTemplate.getSqlSessionFactory().openSession(false);
            sqlSessionUnit.setSimpleSqlSession(simpleSqlSessionTemplate);
            //batch模式
            SqlSessionFactoryBean batchSqlSessionFactoryBean = new SqlSessionFactoryBean();
            batchSqlSessionFactoryBean.setDataSource(dataSource);
            batchSqlSessionFactoryBean.setConfigLocation(this.configLocation);
            SpringManagedTransactionFactory batchTransactionFactory = new SpringManagedTransactionFactory();
            batchSqlSessionFactoryBean.setTransactionFactory(batchTransactionFactory);
            batchSqlSessionFactoryBean.setMapperLocations(mapperLocations);
            batchSqlSessionFactoryBean.setTypeAliasesPackage(typeAliasesPackage);
            SqlSessionFactory batchSessionFacotry = batchSqlSessionFactoryBean.getObject();
            SqlSessionTemplate batchSqlSessionTemplate = new SqlSessionTemplate(batchSessionFacotry);
            batchSqlSessionTemplate.getSqlSessionFactory().openSession(ExecutorType.BATCH, false);
            sqlSessionUnit.setBatchSqlSessions(batchSqlSessionTemplate);
            return sqlSessionUnit;
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw e;
        }
    }

    @Override
    public void destroy() throws Exception {
        if (dataSourceExecutors != null) {
            for (Map.Entry<String, ExecutorService> entry : dataSourceExecutors.entrySet()) {
                try {
                    entry.getValue().shutdown();
                    entry.getValue().awaitTermination(5, TimeUnit.MINUTES);
                    entry.setValue(null);
                } catch (InterruptedException e) {
                    logger.warn("interrupted when shuting down the query executor:\n{}", e);
                }
            }
            dataSourceExecutors.clear();
            logger.debug("all of the executor services in DBSqlSessionTemplate are disposed.");
        }
    }

    // 以下为SQL session接口实现

    @SuppressWarnings("unchecked")
    @Override
    public Object selectOne(String statement) {
        return this.selectOne(statement, null);
    }

    @SuppressWarnings("unchecked")
    @Override
    public Object selectOne(String statement, Object parameter) {
        List<Object> results = null;
        List<String> identitys = lookupDataSourcesByRouter(statement, parameter, StatementType.selectOne);
        results = executeInConcurrency(statement, parameter, identitys, StatementType.selectOne);
        //这里如果出现多库的情况，会返回多条记录，会抛出异常，这里看做正常情况，因为sql没有保证只返回了一条        
        SqlExpressionType sqlExpressionType = SqlSessionHolder.getSqlExpressionType(statement);
        if (sqlExpressionType == null) {
            if (results.size() > 1) {
                throw new IncorrectResultSizeDataAccessException(1);
            } else {
                return results.size() == 0 ? null : results.get(0);
            }
        } else {
            return selectOne(results, sqlExpressionType);
        }

    }

    public List selectPage(String statement, Object parameter, Pagination pagination) {
        List<String> identitys = lookupDataSourcesByRouter(statement, parameter, StatementType.selectList);
        Map<String, Object> params = new HashMap<String, Object>();
        if (parameter != null) {
            params.put("param", parameter);
        }
        params.put("page", pagination);
        List result = (List) executeInConcurrency(statement, params, null, null, identitys, StatementType.selectList);
        return result;
    }

    private Object selectOne(List<Object> results, SqlExpressionType sqlExpressionType) {
//        if (CollectionUtils.isEmpty(results)) {
//            return null;
//        }
//        switch (sqlExpressionType) {
//            case COUNT:
//                return CollectionUtils.sumList(results, ((Comparable<?>) results.get(0)).getClass());
//            case SUM:
//                return CollectionUtils.sumList(results, ((Comparable<?>) results.get(0)).getClass());
//            case MIN:
//                return CollectionUtils.min(results, null, ((Comparable<?>) results.get(0)).getClass());
//            case MAX:
//                return CollectionUtils.max(results, null, ((Comparable<?>) results.get(0)).getClass());
//            default:
        return results.get(0);
//        }
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Override
    public List selectList(String statement) {
        return this.selectList(statement, null);
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Override
    public List selectList(String statement, Object parameter) {
        return this.selectList(statement, parameter, RowBounds.DEFAULT);
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Override
    public List selectList(String statement, Object parameter, RowBounds rowBounds) {
        List<String> identitys = lookupDataSourcesByRouter(statement, parameter, StatementType.selectList);
        List result = (List) executeInConcurrency(statement, parameter, null, (rowBounds == null ? RowBounds.DEFAULT : rowBounds), identitys, StatementType.selectList);
        //判断是否分页分库查询
        if (rowBounds != null && rowBounds.getLimit() > 0 && identitys.size() > 1) {
            return subList(result, rowBounds.getOffset(), rowBounds.getLimit());
        }
        return result;
    }

    private List subList(List list, int startIndex, int recordCount) {
        return list.subList(Math.min(list.size() - 1, startIndex), Math.min(list.size(), startIndex + recordCount));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Override
    public Map selectMap(String statement, String mapKey) {
        return this.selectMap(statement, null, mapKey);
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Override
    public Map selectMap(String statement, Object parameter, String mapKey) {
        return this.selectMap(statement, parameter, mapKey, RowBounds.DEFAULT);
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Override
    public Map selectMap(String statement, Object parameter, String mapKey, RowBounds rowBounds) {
        List<Object> exeResults = null;
        List<String> identitys = lookupDataSourcesByRouter(statement, parameter, StatementType.selectMap);
        exeResults = executeInConcurrency(statement, parameter, mapKey, (rowBounds == null ? RowBounds.DEFAULT : rowBounds), identitys, StatementType.selectMap);
        Map results = new HashMap();// qing:此处强行转换了
        for (Object er : exeResults) {
            Map temp = (Map) er;
            for (Object key : temp.keySet()) {
                results.put(key, temp.get(key));
            }
        }
        return results;
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

    @Override
    public void select(String statement, Object parameter, ResultHandler handler) {
        this.select(statement, parameter, null, handler);
    }

    @Override
    public void select(String statement, ResultHandler handler) {
        this.select(statement, null, handler);
    }

    @Override
    public void select(String statement, Object parameter, RowBounds rowBounds, ResultHandler handler) {
        List<String> identitys = lookupDataSourcesByRouter(statement, parameter, StatementType.select);
        executeInConcurrency(statement, parameter, null, (rowBounds == null ? RowBounds.DEFAULT : rowBounds), handler, identitys, StatementType.select);
    }

    @Override
    public int insert(String statement) {
        return this.insert(statement, null);
    }

    @Override
    public int insert(String statement, Object parameter) {
        List<Object> results = null;

        // 这里支持了同时insert多个对象
        if (parameter != null && parameter instanceof Collection<?>) {
            results = this.batchExecuteInConcurrency(statement, (Collection<?>) parameter, StatementType.insert);
        } else {
            List<String> identitys = lookupDataSourcesByRouter(statement, parameter, StatementType.insert);
            results = executeInConcurrency(statement, parameter, identitys, StatementType.insert);
        }
        Integer rowAffacted = 0;
        for (Object item : results) {
            rowAffacted += (Integer) item;
        }
        return rowAffacted;
    }

    @Override
    public int update(String statement) {
        return this.update(statement, null);
    }

    @Override
    public int update(String statement, Object parameter) {
        List<Object> results = null;
        if (parameter != null && parameter instanceof Collection<?>) {
            results = this.batchExecuteInConcurrency(statement, (Collection<?>) parameter, StatementType.update);
        } else {
            List<String> identitys = lookupDataSourcesByRouter(statement, parameter, StatementType.update);
            results = executeInConcurrency(statement, parameter, identitys, StatementType.update);
        }

        Integer rowAffacted = 0;
        for (Object item : results) {
            rowAffacted += (Integer) item;
        }
        return rowAffacted;
    }

    @Override
    public int delete(String statement) {
        return this.delete(statement, null);
    }

    @Override
    public int delete(String statement, Object parameter) {
        List<Object> results = null;
        if (parameter != null && parameter instanceof Collection<?>) {
            results = this.batchExecuteInConcurrency(statement, (Collection<?>) parameter, StatementType.delete);
        } else {
            List<String> identitys = lookupDataSourcesByRouter(statement, parameter, StatementType.delete);
            results = executeInConcurrency(statement, parameter, identitys, StatementType.delete);
        }
        Integer rowAffacted = 0;
        for (Object item : results) {
            rowAffacted += (Integer) item;
        }
        return rowAffacted;
    }

    private List<String> lookupDataSourcesByRouter(String statementName, Object parameterObject, StatementType crud) {
        return getDataSourceService().lookupDataSourcesByRouter(statementName, parameterObject, crud);
    }

    public boolean isSharding(String statementName, Object parameterObject, StatementType crud) {
        List<String> identies = lookupDataSourcesByRouter(statementName, parameterObject, crud);
        return identies != null && identies.size() > 1;
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
        if (sessionMap.isEmpty()) {
            throw new UnsupportedOperationException("Manual getConfiguration is not allowed over a Spring managed SqlSession, the sqlSession is empty");
        }
        SqlSession sqlSession = (SqlSession) sessionMap.values().toArray()[0];
        return sqlSession.getConfiguration();
    }

    @Override
    public <T> T getMapper(Class<T> type) {
        if (sessionMap.isEmpty()) {
            throw new UnsupportedOperationException("Manual getMapper is not allowed over a Spring managed SqlSession, the sqlSession is empty");
        }
        SqlSession sqlSession = (SqlSession) sessionMap.values().toArray()[0];
        return sqlSession.getMapper(type);
    }

    @Override
    public Connection getConnection() {
        throw new UnsupportedOperationException("Manual getConnection is not allowed over a Spring managed SqlSession");
    }

    private List<Object> executeInConcurrency(String statement, Object parameter, String mapKey, RowBounds rowBounds, List<String> identitys, StatementType crud) {
        return this.executeInConcurrency(statement, parameter, mapKey, rowBounds, null, identitys, crud);
    }

    private List<Object> executeInConcurrency(String statement, Object parameter, String mapKey, RowBounds rowBounds, ResultHandler resultHandler, List<String> identitys, StatementType crud) {
        logger.debug("Sharding log->Statement：" + statement + "，parameter：" + parameter);
        long startTimestamp = System.currentTimeMillis();
        List<ConcurrentRequest> requests = new ArrayList<ConcurrentRequest>();
        List<Object> results = new ArrayList<Object>();
        try {
            for (String identity : identitys) {
                ConcurrentRequest request = new ConcurrentRequest();
                request.setStatement(statement);
                request.setParameter(parameter);
                // 每个ConcurrentRequest不共用RowBounds
                if (rowBounds != null) {
                    request.setRowBounds(new RowBounds(rowBounds.getOffset(), rowBounds.getLimit()));
                }
                request.setSqlSession(this.sessionMap.get(identity));
                request.setDataSourceName(identity);
                request.setMapKey(mapKey);
                request.setCrud(crud);
                request.setExecutor(dataSourceExecutors.get(identity));
                request.setResultHandler(resultHandler);
                requests.add(request);
            }
            if (requests.size() == 1) {
                Object result = this.concurrentRequestProcessor.executeWith(requests.get(0));
                if (result instanceof List) {
                    @SuppressWarnings("unchecked") List<Object> list = (List<Object>) result;
                    results.addAll(list);
                } else if (result != null) {
                    results.add(result);
                }
            } else {
                // qing 2012-12-11 这3种情况单线程执行，因如果多库多线程无法纳入分布式事务的问题，当然事务还有赖于用户事务注解
                if (crud == StatementType.insert || crud == StatementType.update || crud == StatementType.delete) {
                    for (ConcurrentRequest obj : requests) {
                        Object result = this.concurrentRequestProcessor.executeWith(obj);
                        results.add(result);
                    }
                } else {
                    try {
                        if (!mutiThreadExcuteSelect) {
                            try {
                                SqlSessionHolder.setSharding();
                                for (ConcurrentRequest obj : requests) {
                                    Object result = this.concurrentRequestProcessor.executeWith(obj);
                                    results.add(result);
                                }
                            } finally {
                                SqlSessionHolder.clearSharding();
                            }

                        } else {
                            List<Object> result = this.concurrentRequestProcessor.process(requests);
                            results.addAll(result);
                        }
//                        if (CollectionUtils.isNotEmpty(SqlSessionHolder.getOrderBy(requests.get(0).getStatement()))) {
//                            CollectionUtils.sort(results, SqlSessionHolder.getOrderBy(requests.get(0).getStatement()));
//                        }
                    } finally {
                        SqlSessionHolder.clearOrderBy(requests.get(0).getStatement());
                    }
                }

            }
            long endTimestamp = System.currentTimeMillis();
            if ((endTimestamp - startTimestamp) > sqlExecTimeThreshold) {
                logger.warn("statement:" + statement + ". cost time:" + (endTimestamp - startTimestamp) + ". parameter: " + JSON.toJSONString(parameter) + ". identitys" + JSON.toJSONString(identitys));
            }
            if (results != null && results.size() > sqlSelectCountThreshold) {
                logger.warn("statement:" + statement + ". sqlSelectCount:" + results.size() + ". parameter: " + JSON.toJSONString(parameter) + ". identitys" + JSON.toJSONString(identitys));
            }
            return results;
        } catch (Exception exp) {
            throw new RuntimeException(exp);
        }
    }


    /**
     * SQL执行
     */
    private List<Object> executeInConcurrency(String statement, Object parameter, List<String> identitys, StatementType crud) {
        return this.executeInConcurrency(statement, parameter, null, null, identitys, crud);
    }

    public List<Object> executeInConcurrencyMap(String statement, Object parameter, String mapKey, RowBounds rowBounds, List<String> identitys) {
        return this.executeInConcurrency(statement, parameter, mapKey, rowBounds, identitys, StatementType.selectMap);
    }

    //创建多路由的多线程处理器
    private ExecutorService createCustomExecutorService(int poolSize, final String name) {
        int coreSize = Runtime.getRuntime().availableProcessors();
        if (poolSize < coreSize) {
            coreSize = poolSize;
        }
        ThreadFactory tf = new ThreadFactory() {

            public Thread newThread(Runnable r) {
                Thread t = new Thread(r, name);
                t.setDaemon(true);
                return t;
            }
        };
        BlockingQueue<Runnable> queueToUse = new LinkedBlockingQueue<Runnable>();
        final ThreadPoolExecutor executor = new ThreadPoolExecutor(coreSize, poolSize, 60, TimeUnit.SECONDS, queueToUse, tf, new ThreadPoolExecutor.CallerRunsPolicy());
        Runtime.getRuntime().addShutdownHook(new Thread() {

            @SuppressWarnings("unused")
            @Override
            public void run() {
                if (executor == null) {
                    return;
                }
                try {
                    executor.shutdown();
                    executor.awaitTermination(5, TimeUnit.MICROSECONDS);
                } catch (InterruptedException e) {
                    logger.warn("interrupted when shuting down the query executor:\n{}", e);
                }
            }
        });
        return executor;
    }

    /**
     * 批量执行SQL，仅支持一条SQL多个参数对象
     *
     * @param statement
     * @param paramCol
     * @return
     */
    public List<Object> batchExecuteInConcurrency(final String statement, Collection<?> paramCol, StatementType crud) {
        if (paramCol == null) {
            return null;
        }
        logger.debug("Sharding log->Statement：" + statement + "，parameter：" + paramCol);

        Map<String, List<Object>> parameterMap = new HashMap<String, List<Object>>();
        Iterator<?> iter = paramCol.iterator();
        while (iter.hasNext()) {
            Object paramObject = iter.next();
            List<String> identitys = lookupDataSourcesByRouter(statement, paramObject, crud);
            for (String identity : identitys) {
                if (!parameterMap.containsKey(identity)) {
                    parameterMap.put(identity, new ArrayList<Object>());
                }
                parameterMap.get(identity).add(paramObject);
            }
        }
        List<ConcurrentRequest> requests = new ArrayList<ConcurrentRequest>();
        for (String dsName : parameterMap.keySet()) {
            ConcurrentRequest request = new ConcurrentRequest();
            request.setSqlSession(this.sessionMap.get(dsName));
            request.setDataSourceName(dsName);
            request.setStatement(statement);
            request.setParameter(parameterMap.get(dsName));
            request.setCrud(crud);
            request.setExecutorType(ExecutorType.BATCH);
            request.setExecutor(dataSourceExecutors.get(dsName));
            requests.add(request);
        }
        // qing 2012-12-11 解决多线程执行没有分布式事务的问题
        if (crud == StatementType.update || crud == StatementType.insert || crud == StatementType.delete) {
            // 这3种情况，单线程执行
            List<Object> results = new ArrayList<Object>();
            for (ConcurrentRequest obj : requests) {
                Object result = this.concurrentRequestProcessor.executeWith(obj);
                results.add(result);
            }
            return results;
        } else {
            if (requests.size() == 1) {
                List<Object> results = new ArrayList<Object>();
                Object result = this.concurrentRequestProcessor.executeWith(requests.get(0));
                if (result instanceof List) {
                    @SuppressWarnings("unchecked") List<Object> list = (List<Object>) result;
                    results.addAll(list);
                } else {
                    results.add(result);
                }
                return results;
            } else {
                return this.concurrentRequestProcessor.process(requests);//多线程并发
            }
        }
    }

    public void setMutiThreadExcuteSelect(boolean mutiThreadExcuteSelect) {
        this.mutiThreadExcuteSelect = mutiThreadExcuteSelect;
    }
}
