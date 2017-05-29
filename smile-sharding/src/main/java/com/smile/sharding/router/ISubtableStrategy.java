package com.smile.sharding.router;

/**
 * 
 * <pre>
 * @author 潘明国
 * 应用实现这个接口来实现分表策略
 * 创建日期: 2013-7-5
 * 修改人 :  
 * 修改说明: 
 * 评审人 ：
 * </pre>
 */
public interface ISubtableStrategy {

    /**
     * 路由表
     */
    String getTable();

    /**
     * 返回表
     * @param value 执行参数的对象
     * @return
     */
    String getRouterResult(Object value);
}
