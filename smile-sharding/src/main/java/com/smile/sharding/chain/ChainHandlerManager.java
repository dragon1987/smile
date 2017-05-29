package com.smile.sharding.chain;

import com.smile.sharding.enums.StatementType;

import java.util.ArrayList;

/*
 * 所有的 chain执行器，注入到这个类中
 * 该类正式用时，要改成静态或单例，并做线程处理
 */
public class ChainHandlerManager  {
	private ArrayList<IChainHandler> handlerList;

	public void setHandlerList(ArrayList<IChainHandler> handlerList) {
		this.handlerList = handlerList;
	}

	public ArrayList<IChainHandler> getHandlerList() {
		return handlerList;
	}
	
	public void process(Object parameter,StatementType statementType){
		for(IChainHandler handler :handlerList){
			boolean flat = handler.execute(parameter, statementType);
			if(flat){
				return;
			}
		}
	}
}
