package com.smile.sharding.chain;

import com.smile.sharding.enums.StatementType;

public interface IChainHandler  {
	/**
	 * @param parameter sql执行时的参数实体对象
	 * @param statementType insert,update,delete
	 * @return 是否执行完成继续传给下一个处理器，true为不传递
	 */
    boolean execute(Object parameter, StatementType statementType);
}
