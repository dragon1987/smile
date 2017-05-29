package com.smile.sharding.cache;

import java.util.List;

/**
 * Created by zhutao on 2014/12/3.
 */
public interface ICache {

    /**
     * 设置过期时间
     * @param key
     */
    void expire(String key);

    /**
     * 添加数据
     * @param key
     * @param data
     */
    void add(String key, String data);

    /**
     * 删除数据
     * @param key
     */
    void remove(String key);

    /**
     * 获取数据
     * @param key
     * @param start 开始位置
     * @param length 长度
     * @return
     */
    List<String> fetch(String key, int start, int length);


}
