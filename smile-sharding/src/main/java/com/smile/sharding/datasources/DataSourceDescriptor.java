package com.smile.sharding.datasources;

import com.smile.sharding.loadbalance.IDBLoadBalance;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.jdbc.datasource.LazyConnectionDataSourceProxy;

import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.List;

/*
 * 对组数据源的描述 ，一主多从，可实现读写分离
 */
public class DataSourceDescriptor implements InitializingBean {

    /**
     * 数据源组标识
     */
    private String identity;

    /**
     * 主数据源
     */
    private DataSource masterDataSource;

    /**
     * 从数据源,可有多个
     */
    private List<DataSource> slaveDataSources;

    /**
     * 是否开启读写分离
     */
    private boolean readWriteSplit = false;

    /**
     * 读写分离路由规则
     */
    private IDBLoadBalance dbLoadBalance;

    // 单个数据源的池最大值线程数，仅在一sql多数据源时使用。可配置改变默认值
    private int threadPoolSize = Runtime.getRuntime().availableProcessors() * 5;

    public boolean isReadWriteSplit() {
        return readWriteSplit;
    }

    public void setReadWriteSplit(boolean readWriteSplit) {
        this.readWriteSplit = readWriteSplit;
    }

    public String getIdentity() {
        return identity;
    }

    public void setIdentity(String identity) {
        this.identity = identity;
    }

    public int getThreadPoolSize() {
        return threadPoolSize;
    }

    public void setThreadPoolSize(int threadPoolSize) {
        this.threadPoolSize = threadPoolSize;
    }

    public DataSource getMasterDataSource() {
        return masterDataSource;
    }

    public void setMasterDataSource(DataSource masterDataSource) {
        this.masterDataSource = masterDataSource;
    }

    public List<DataSource> getSlaveDataSources() {
        return slaveDataSources;
    }

    public void setSlaveDataSources(List<DataSource> slaveDataSources) {
        this.slaveDataSources = slaveDataSources;
    }

    public IDBLoadBalance getDbLoadBalance() {
        return dbLoadBalance;
    }

    public void setDbLoadBalance(IDBLoadBalance dbLoadBalance) {
        this.dbLoadBalance = dbLoadBalance;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        masterDataSource = new LazyConnectionDataSourceProxy(masterDataSource);
        if (slaveDataSources != null && slaveDataSources.size() > 0) {
            List<DataSource> slaveLazyDataSources = new ArrayList<DataSource>();
            for (DataSource dataSource : slaveDataSources) {
                slaveLazyDataSources.add(new LazyConnectionDataSourceProxy(dataSource));
            }
            slaveDataSources = slaveLazyDataSources;
        }
    }

}
