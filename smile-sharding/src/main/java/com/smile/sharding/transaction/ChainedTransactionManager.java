package com.smile.sharding.transaction;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.sql.DataSource;

import org.apache.commons.lang3.Validate;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.HeuristicCompletionException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionException;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.UnexpectedRollbackException;

import com.smile.sharding.enums.StatementType;
import com.smile.sharding.datasources.IDataSourceService;
import com.smile.sharding.execution.ConcurrentRequest;

public class ChainedTransactionManager implements PlatformTransactionManager, InitializingBean {

    private final static Log logger = LogFactory.getLog(ChainedTransactionManager.class);

    private List<PlatformTransactionManager> transactionManagers;

    private SynchronizationManager synchronizationManager;

    private IDataSourceService dataSourceService;

    private String tranFailPath ;

    private Map<PlatformTransactionManager, String> mapTranManageDsDesc = new HashMap<PlatformTransactionManager, String>();

    private TranFailHandler tranErrorHandler = new TranFailHandler();

    public void setDataSourceService(IDataSourceService dataSourceService) {
        this.dataSourceService = dataSourceService;
    }

    public IDataSourceService getDataSourceService() {
        return dataSourceService;
    }

    public void afterPropertiesSet() throws Exception {
        Validate.notNull(dataSourceService);
        synchronizationManager = new DefaultSynchronizationManager();
        transactionManagers = new ArrayList<PlatformTransactionManager>();

        for (Map.Entry<String, DataSource> entry : getDataSourceService().getDataSources().entrySet()) {
            DataSourceTransactionManager txManager = new DataSourceTransactionManager(entry.getValue());
            transactionManagers.add(txManager);
            mapTranManageDsDesc.put(txManager, entry.getKey());
        }
        Collections.reverse(transactionManagers);
    }

    /*
     * qing 2012-08-29 我在这里默认给他们分配jdbc的事务管理器,如果需要支持其它类型 如jta可以另外定义 public
     * ChainedTransactionManager(PlatformTransactionManager...
     * transactionManagers) { this(new
     * DefaultSynchronizationManager(),transactionManagers); }
     * 
     * public ChainedTransactionManager(SynchronizationManager
     * synchronizationManager, PlatformTransactionManager...
     * transactionManagers) { this.synchronizationManager =
     * synchronizationManager;
     * this.transactionManagers=asList(transactionManagers); }
     */

    @Override
    public MultiTransactionStatus getTransaction(TransactionDefinition definition) throws TransactionException {
        MultiTransactionStatus mts = new MultiTransactionStatus(transactionManagers.get(0)/*
                                                                                           * First
                                                                                           * TM
                                                                                           * is
                                                                                           * main
                                                                                           * TM
                                                                                           */);

        if (!synchronizationManager.isSynchronizationActive()) {
            synchronizationManager.initSynchronization();
            mts.setNewSynchonization();
        }

        for (PlatformTransactionManager transactionManager : transactionManagers) {
            mts.registerTransactionManager(definition, transactionManager);
        }

        //标识事务开始了，用于记录事务的sql,param等信息
        TransactionRequestHolder.setInTransaction(true);

        return mts;
    }

    @Override
    public void commit(TransactionStatus status) throws TransactionException {

        MultiTransactionStatus multiTransactionStatus = (MultiTransactionStatus) status;

        boolean commit = true;
        Exception commitException = null;
        PlatformTransactionManager commitExceptionTransactionManager = null;
        Map<String, List<ConcurrentRequest>> mapTranManageRequest = new HashMap<String, List<ConcurrentRequest>>();

        for (PlatformTransactionManager transactionManager : reverse(transactionManagers)) {
            if (commit) {
                try {
                    multiTransactionStatus.commit(transactionManager);
                } catch (Exception ex) {
                    commit = false;
                    commitException = ex;
                    commitExceptionTransactionManager = transactionManager;
                    logger.error("transaction commit error: " + ex.getMessage(),ex);
                    collectConcurrentRequest(mapTranManageRequest, transactionManager);
                }
            } else {
                //after unsucessfull commit we must try to rollback remaining transaction managers
                try {
                    multiTransactionStatus.rollback(transactionManager);
                } catch (Exception ex) {
                    logger.warn("Rollback exception (after commit) (" + transactionManager + ") " + ex.getMessage(), ex);
                }
                collectConcurrentRequest(mapTranManageRequest, transactionManager);
            }
        }

        if (multiTransactionStatus.isNewSynchonization()) {
            synchronizationManager.clearSynchronization();
        }

        //将thread local中的信息清掉
        TransactionRequestHolder.cleanRequests();        

        if (commitException != null) {
            boolean firstTransactionManagerFailed = commitExceptionTransactionManager == getLastTransactionManager();
            int transactionState = firstTransactionManagerFailed ? HeuristicCompletionException.STATE_ROLLED_BACK
                    : HeuristicCompletionException.STATE_MIXED;

            HeuristicCompletionException heuristicCompletionException = new HeuristicCompletionException(
                    transactionState, commitException);

            tranErrorHandler.doCompensate(mapTranManageRequest, heuristicCompletionException, tranFailPath);
            throw heuristicCompletionException;
        }

    }

    /**
     * @param mapTranManageRequest
     * @param transactionManager
     */
    private void collectConcurrentRequest(Map<String, List<ConcurrentRequest>> mapTranManageRequest,
            PlatformTransactionManager transactionManager) {
        // 收集该db上执行失败的ConcurrentRequest
        for (ConcurrentRequest request : TransactionRequestHolder.getRequests()) {
            if (request.getCrud().equals(StatementType.insert)
                    || request.getCrud().equals(StatementType.update)
                    || request.getCrud().equals(StatementType.delete)) {
                String dsDesc = dataSourceService.getDataSourceDescriptor(request.getDataSourceName())
                        .getIdentity();
                if (mapTranManageDsDesc.get(transactionManager).equals(dsDesc)) {
                    if (!mapTranManageRequest.containsKey(dsDesc)) {
                        mapTranManageRequest.put(dsDesc, new ArrayList<ConcurrentRequest>());
                    }
                    mapTranManageRequest.get(dsDesc).add(request);
                }
            }
        }
    }

    @Override
    public void rollback(TransactionStatus status) throws TransactionException {

        Exception rollbackException = null;
        PlatformTransactionManager rollbackExceptionTransactionManager = null;

        MultiTransactionStatus multiTransactionStatus = (MultiTransactionStatus) status;

        for (PlatformTransactionManager transactionManager : reverse(transactionManagers)) {
            try {
                multiTransactionStatus.rollback(transactionManager);
            } catch (Exception ex) {
                if (rollbackException == null) {
                    rollbackException = ex;
                    rollbackExceptionTransactionManager = transactionManager;
                    // qing:
                    logger.error("transaction rollback error:" + ex.getMessage(),ex);
                } else {
                    logger.warn("Rollback exception (" + transactionManager + ") " + ex.getMessage(), ex);
                }
            }
        }

        if (multiTransactionStatus.isNewSynchonization()) {
            synchronizationManager.clearSynchronization();
        }

        //将thread local中的信息清掉
        TransactionRequestHolder.cleanRequests();   

        if (rollbackException != null) {
            throw new UnexpectedRollbackException("Rollback exception, originated at ("
                    + rollbackExceptionTransactionManager + ") " + rollbackException.getMessage(), rollbackException);
        }
    }

    private <T> Iterable<T> reverse(Collection<T> collection) {
        List<T> list = new ArrayList<T>(collection);
        Collections.reverse(list);
        return list;
    }

    private PlatformTransactionManager getLastTransactionManager() {
        return transactionManagers.get(lastTransactionManagerIndex());
    }

    private int lastTransactionManagerIndex() {
        return transactionManagers.size() - 1;
    }

    public String getTranFailPath() {
        return tranFailPath;
    }

    public void setTranFailPath(String tranFailPath) {
        this.tranFailPath = tranFailPath;
    }

}