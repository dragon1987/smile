package com.smile.sharding.transaction;

import com.smile.sharding.log.TranFailLog;
import com.smile.sharding.execution.ConcurrentRequest;
import com.smile.sharding.log.MonitorLogUtils;
import org.apache.ibatis.mapping.BoundSql;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.mapping.ParameterMapping;
import org.apache.ibatis.mapping.ParameterMode;
import org.apache.ibatis.reflection.MetaObject;
import org.apache.ibatis.reflection.property.PropertyTokenizer;
import org.springframework.transaction.HeuristicCompletionException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * 
 * <pre>
 * @author：hudi
 * 
 * 事务失败将相关信息记录日志
 * 创建日期: 2012-11-1
 * 修改人 :  hudi
 * 修改说明: 2012-11-1
 * 评审人 ：
 * </pre>
 */
public class TranFailHandler {

	public void doCompensate(Map<String, List<ConcurrentRequest>> mapTranManageRequest,
			HeuristicCompletionException expception,String tranFailPath) {
		try {
			Map<String, List<TranFailLog>> maplogInfo = new HashMap<String, List<TranFailLog>>();
			for (Map.Entry<String, List<ConcurrentRequest>> entry : mapTranManageRequest.entrySet()) {
				for (ConcurrentRequest request : entry.getValue()) {
					String sql = request.getSqlSession().getConfiguration().getMappedStatement(request.getStatement())
							.getBoundSql(request.getParameter()).getSql();

					Object[] paramValues = getParamValues(request.getParameter(), request.getSqlSession()
							.getConfiguration().getMappedStatement(request.getStatement()));

					TranFailLog logInfo = new TranFailLog();

					logInfo.setSqlStatement(sql);
					logInfo.setParam(paramValues);
					logInfo.setDatasourceId(entry.getKey());
					logInfo.setExceptionCause(expception.getMessage());

					List<TranFailLog> logInfos = maplogInfo.get(logInfo.getDatasourceId());
					if (logInfos == null) {
						logInfos = new ArrayList<TranFailLog>();
						maplogInfo.put(logInfo.getDatasourceId(), logInfos);
					}
					logInfos.add(logInfo);
				}
			}

			for (Map.Entry<String, List<TranFailLog>> entry : maplogInfo.entrySet()) {
				MonitorLogUtils.writeTranFailLog(entry.getValue(),tranFailPath);
			}
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private Object[] getParamValues(Object parameterObject, MappedStatement ms) {
		BoundSql boundSql = ms.getBoundSql(parameterObject);
		List<ParameterMapping> parameterMappings = boundSql.getParameterMappings();
		List<Object> result = new ArrayList<Object>();
		if (parameterMappings != null) {
			MetaObject metaObject = parameterObject == null ? null : ms.getConfiguration().newMetaObject(
					parameterObject);
			for (int i = 0; i < parameterMappings.size(); i++) {
				ParameterMapping parameterMapping = parameterMappings.get(i);
				if (parameterMapping.getMode() != ParameterMode.OUT) {
					Object value;
					String propertyName = parameterMapping.getProperty();
					PropertyTokenizer prop = new PropertyTokenizer(propertyName);
					if (parameterObject == null) {
						value = null;
					} else if (ms.getConfiguration().getTypeHandlerRegistry()
							.hasTypeHandler(parameterObject.getClass())) {
						value = parameterObject;
					} else if (boundSql.hasAdditionalParameter(propertyName)) {
						value = boundSql.getAdditionalParameter(propertyName);
					}  else {
						value = metaObject == null ? null : metaObject.getValue(propertyName);
					}

					result.add(value);
				}
			}
		}

		return result.toArray(new Object[result.size()]);
	}
}
