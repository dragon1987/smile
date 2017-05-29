package com.smile.sharding.plugin;

import com.smile.sharding.page.Pagination;
import com.smile.sharding.router.ISubtableRouterManager;
import com.smile.sharding.sqlParser.TablesNamesVisit;
import net.sf.jsqlparser.JSQLParserException;
import net.sf.jsqlparser.parser.CCJSqlParserUtil;
import net.sf.jsqlparser.statement.Statement;
import org.apache.ibatis.session.ResultHandler;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

import java.util.HashMap;
import java.util.Map;

public class SubtableUtil implements ApplicationContextAware {

    private static ISubtableRouterManager subtableRouterManager;

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        subtableRouterManager = applicationContext.getBean(ISubtableRouterManager.class);
    }

    public static String getSubtabledSql(String sql, Object paramObj) throws JSQLParserException {
        if (subtableRouterManager == null) {
            return sql;
        }
        if ((paramObj instanceof HashMap)) {
            Map<String, Object> params = new HashMap<String, Object>();
            for (Map.Entry<String, Object> entry : ((HashMap<String, Object>) paramObj).entrySet()) {
                if (entry.getValue() instanceof ResultHandler) {
                    continue;
                }
                if (entry.getValue() instanceof Pagination) {
                    continue;
                }
                params.put(entry.getKey(), entry.getValue());
            }
            if (params.size() == 1) {
                TablesNamesVisit tablesNamesVisit = new TablesNamesVisit(subtableRouterManager, params.values().toArray()[0]);
                Statement statement = CCJSqlParserUtil.parse(sql);
                statement.accept(tablesNamesVisit);
                return statement.toString();
            } else {
                TablesNamesVisit tablesNamesVisit = new TablesNamesVisit(subtableRouterManager, params);
                Statement statement = CCJSqlParserUtil.parse(sql);
                statement.accept(tablesNamesVisit);
                return statement.toString();
            }

        } else {
            TablesNamesVisit tablesNamesVisit = new TablesNamesVisit(subtableRouterManager, paramObj);
            Statement statement = CCJSqlParserUtil.parse(sql);
            statement.accept(tablesNamesVisit);
            return statement.toString();
        }

    }
}
