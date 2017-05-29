package com.smile.sharding.transaction;

import java.util.ArrayList;
import java.util.List;

import com.smile.sharding.execution.ConcurrentRequest;

/*
 * todo: 这个类的作用还待讨论
 */
public class TransactionRequestHolder {

	private static ThreadLocal<List<ConcurrentRequest>> concurrentRequests = new ThreadLocal<List<ConcurrentRequest>>();

	private static ThreadLocal<Boolean> isInTransaction = new ThreadLocal<Boolean>();

	public static void addRequest(ConcurrentRequest request) {
		if (Boolean.TRUE.equals(isInTransaction.get())) {
			if (concurrentRequests.get() == null) {
				concurrentRequests.set(new ArrayList<ConcurrentRequest>());
			}
			concurrentRequests.get().add(request);
		}
	}

	public static List<ConcurrentRequest> getRequests() {
		return concurrentRequests.get();
	}

	public static void setInTransaction(boolean inTransaction) {
		isInTransaction.set(inTransaction);
	}

	public static void cleanRequests() {
		if (concurrentRequests.get() != null) {
			concurrentRequests.get().clear();
		}
		//isInTransaction.set(Boolean.FALSE);
		concurrentRequests.remove();
		isInTransaction.remove();
	}
}
