package com.smile.sharding.execution;

import com.smile.sharding.sqlSession.SqlSessionHolder;
import com.smile.sharding.transaction.TransactionRequestHolder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ibatis.session.SqlSession;
import org.springframework.dao.ConcurrencyFailureException;
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;


/*
 * 目前，process只处理select*请求,其它可能有多线程分布式事务问题
 * 
 * @author qing
 */
public class DefaultConcurrentRequestProcessor implements IConcurrentRequestProcessor {

    private final Log logger = LogFactory.getLog(getClass());

    @Override
    public List<Object> process(List<ConcurrentRequest> requests) {
        List<Object> resultList = new ArrayList<Object>();
        if (CollectionUtils.isEmpty(requests)) {
            return resultList;
        }
        final CountDownLatch latch = new CountDownLatch(requests.size());
        List<Future<Object>> futures = new ArrayList<Future<Object>>();
        for (int i = 0; i < requests.size(); i++) {
            final ConcurrentRequest request = requests.get(i);
            futures.add(request.getExecutor().submit(new Callable<Object>() {

                public Object call() throws Exception {
                    try {
                        SqlSessionHolder.setSharding();
                        return innerExecuteWith(request);
                    } finally {
                        SqlSessionHolder.clearSharding();
                        latch.countDown();
                    }
                }
            }));
        }
        try {
            latch.await();
        } catch (InterruptedException e) {
            throw new ConcurrencyFailureException("interrupted when processing data access request in concurrency", e);
        }
        logger.debug("begin fillResultListWithFutureResults");
        fillResultListWithFutureResults(futures, resultList);
        return resultList;
    }

    /**
     * all sql execute in there
     *
     * @param request
     * @return
     */
    public Object executeWith(ConcurrentRequest request) {
        TransactionRequestHolder.addRequest(request);
        return this.innerExecuteWith(request);
    }

    private Object innerExecuteWith(ConcurrentRequest request) {
        try {
            SqlSession session = request.getSqlSession();
            Object result = null;
            switch (request.getCrud()) {
                case insert:
                    result = session.insert(request.getStatement(), request.getParameter());
                    break;
                case update:
                    result = session.update(request.getStatement(), request.getParameter());
                    break;
                case delete:
                    result = session.delete(request.getStatement(), request.getParameter());
                    break;
                case selectList:
                    if (request.getResultHandler() == null) {
                        if (request.getRowBounds() == null) {
                            result = session.selectList(request.getStatement(), request.getParameter());
                        } else {
                            result = session.selectList(request.getStatement(), request.getParameter(), request.getRowBounds());
                        }
                    } else {
                        session.select(request.getStatement(), request.getParameter(), request.getResultHandler());
                    }
                    break;
                case select:
                    if (request.getRowBounds() == null) {
                        session.select(request.getStatement(), request.getParameter(), request.getResultHandler());
                    } else {
                        session.select(request.getStatement(), request.getParameter(), request.getRowBounds(), request.getResultHandler());
                    }
                    break;
                case selectOne:
                    result = session.selectOne(request.getStatement(), request.getParameter());
                    break;
                case selectMap:
                    result = session.selectMap(request.getStatement(), request.getParameter(), request.getMapKey(), request.getRowBounds());
                    break;

                default:
                    throw new RuntimeException("can't excetue crud " + request.getCrud());
            }
            return result;
        } catch (Throwable t) {
            logger.error(t.getMessage(), t);
            throw new RuntimeException(t);
        }
    }

    @SuppressWarnings("rawtypes")
    private void fillResultListWithFutureResults(List<Future<Object>> futures, List<Object> resultList) {
        for (Future<Object> future : futures) {
            try {
                if (future.get() == null) {
                    continue;
                }

                // qing: select list返回的是 arraylist，这里处理一下
                if (future.get() instanceof ArrayList) {
                    ArrayList list = (ArrayList) future.get();
                    if (list.size() > 0) {
                        for (Object obj : list) {
                            resultList.add(obj);
                        }
                    }
                } else {
                    resultList.add(future.get());
                }
            } catch (InterruptedException e) {
                throw new ConcurrencyFailureException("interrupted when processing data access request in concurrency", e);
            } catch (ExecutionException e) {
                throw new ConcurrencyFailureException("something goes wrong in processing", e);
            }
        }
    }
}
