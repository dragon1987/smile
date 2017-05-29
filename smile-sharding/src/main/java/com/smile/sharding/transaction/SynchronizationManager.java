package com.smile.sharding.transaction;

public interface SynchronizationManager {

	void initSynchronization();

	boolean isSynchronizationActive();

	void clearSynchronization();
}
