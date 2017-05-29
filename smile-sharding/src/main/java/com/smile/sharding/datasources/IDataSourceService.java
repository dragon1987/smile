package com.smile.sharding.datasources;

import com.smile.sharding.enums.StatementType;

import javax.sql.DataSource;
import java.util.List;
import java.util.Map;
import java.util.Set;

public interface IDataSourceService {

    Map<String, DataSource> getDataSources();

    DataSourceDescriptor getDataSourceDescriptor(String identity);

    Set<DataSourceDescriptor> getDataSourceDescriptors();

    List<String> lookupDataSourcesByRouter(String statementName, Object parameterObject, StatementType crud);

}
