package com.smile.sharding.utils;

import java.lang.reflect.Array;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

public class MapUtils {

	public static boolean isEmpty(Map<?, ?> map) {
		return (map == null || map.isEmpty());
	}

	public static boolean isNotEmpty(Map<?, ?> map) {
		return !MapUtils.isEmpty(map);
	}

	/**
	 * 将一个array转为根据keys转为map
	 * 
	 * @param array
	 * @param keys
	 * @return
	 */
	@SuppressWarnings("all")
	public static Map toMap(Object[] array, String... keys) {
		if (array == null)
			return new HashMap();
		Map m = new LinkedHashMap();
		for (int i = 0; i < keys.length; i++) {
			if (array.length == i) {
				break;
			}
			m.put(keys[i], array[i]);
		}
		return m;
	}

	/**
	 * 可以用于判断 Map,Collection,String,Array是否为空
	 * 
	 * @param o
	 * @return
	 */
	@SuppressWarnings("all")
	public static boolean isEmpty(Object o) {
		if (o == null)
			return true;

		if (o instanceof String) {
			if (((String) o).length() == 0) {
				return true;
			}
		} else if (o instanceof Collection) {
			if (((Collection) o).isEmpty()) {
				return true;
			}
		} else if (o.getClass().isArray()) {
			if (Array.getLength(o) == 0) {
				return true;
			}
		} else if (o instanceof Map) {
			if (((Map) o).isEmpty()) {
				return true;
			}
		} else {
			return false;
		}

		return false;
	}

	/**
	 * 可以用于判断 Map,Collection,String,Array是否不为空
	 * 
	 * @param c
	 * @return
	 */
	public static boolean isNotEmpty(Object c) throws IllegalArgumentException {
		return !isEmpty(c);
	}

}
