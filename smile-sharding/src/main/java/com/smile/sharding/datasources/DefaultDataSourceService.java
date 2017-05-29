package com.smile.sharding.datasources;

import com.smile.sharding.enums.StatementType;
import com.smile.sharding.router.IRouterManager;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

import javax.sql.DataSource;
import java.util.*;

public class DefaultDataSourceService implements IDataSourceService, InitializingBean {

    private Map<String, DataSource> dataSources = new HashMap<String, DataSource>();

    private Set<DataSourceDescriptor> dataSourceDescriptors = new HashSet<DataSourceDescriptor>();

    private Map<String, DataSourceDescriptor> dataSourceMap = new HashMap<String, DataSourceDescriptor>();

    private IRouterManager routerManager;

    private String defaultIdentity;

    public void setDataSourceDescriptors(Set<DataSourceDescriptor> dataSourceDescriptors) {
        this.dataSourceDescriptors = dataSourceDescriptors;
    }

    @Override
    public Set<DataSourceDescriptor> getDataSourceDescriptors() {
        return dataSourceDescriptors;
    }

    @Override
    public Map<String, DataSource> getDataSources() {
        return dataSources;
    }


    public IRouterManager getRouterManager() {
        return routerManager;
    }

    public void setRouterManager(IRouterManager routerManager) {
        this.routerManager = routerManager;
    }

    @Override
    public DataSourceDescriptor getDataSourceDescriptor(String identity) {
        return dataSourceMap.get(identity);
    }

    public List<String> lookupDataSourcesByRouter(String statementName, Object parameterObject, StatementType crud) {
        List<String> identitys = new ArrayList<String>();
        if (!isPartitioningBehaviorEnabled()) {
            identitys.add(defaultIdentity);
            return identitys;
        }

        String result = null;
        result = getRouterManager().getRouterResult(statementName, parameterObject);
        if (result != null) {
            if (result.indexOf(",") > 0) {
                // 这里是暂定的多数据源情况
                String[] temps = result.split(",");
                for (String temp : temps) {
                    identitys.add(temp);
                }
            } else {
                // 单数据源
                identitys.add(result);
            }
        } else {
            // 路由结果为空时的处理
            if (crud == StatementType.insert || crud == StatementType.update || crud == StatementType.delete) {
                throw new RuntimeException("对数据库操作类型为" + crud + "的" + statementName + "必须实现路由策略！");
            }
            // qing, select时，没有找到路由则是返回全部数据源
            //            Map<String, DataSource> map = getDataSources();
            //            for (String dsName : map.keySet()) {
            //                identitys.add(dsName);
            //            }
            //zhutao select时，没有找到路由则是返回默认的
            identitys.add(defaultIdentity);
        }
        return identitys;
    }

    public void afterPropertiesSet() throws Exception {
        initDataSources();
    }

    private void initDataSources() {
        for (DataSourceDescriptor desc : this.getDataSourceDescriptors()) {
            dataSources.put(desc.getIdentity(), desc.getMasterDataSource());
            dataSourceMap.put(desc.getIdentity(), desc);
        }
    }


    private boolean isPartitioningBehaviorEnabled() {
        Assert.notNull(defaultIdentity, "defaultIdentity  must not be null");
        return routerManager != null;
    }

    public void setDefaultIdentity(String defaultIdentity) {
        this.defaultIdentity = defaultIdentity;
    }
}
