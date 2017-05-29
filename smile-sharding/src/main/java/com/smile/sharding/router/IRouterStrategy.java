package com.smile.sharding.router;

/**
 * 应用实现这个接口来实现路由策略 支持水平拆分:范围,哈希,取模... 垂直拆分:直接返回数据源标识即可 可以针对每种entity来定义一种策略
 *
 * @author qing
 */

public interface IRouterStrategy {

    /**
     * 目前RouterKey只支持 mybatis命名空间，mybatis命名空间+mapperId,参数类名，参数包名
     *
     * @return
     */
    String getRouterKey();

    /**
     * 路由规则，根据参数定位到不同数据源上
     *
     * @param value
     * @return
     */
    String getRouterResult(Object value);
}
