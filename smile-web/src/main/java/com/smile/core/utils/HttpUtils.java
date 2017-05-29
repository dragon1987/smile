//package com.smile.core.utils;
//
//import com.smile.core.HttpContext;
//import com.smile.sharding.utils.MapUtils;
//import org.apache.http.HttpEntity;
//import org.apache.http.NameValuePair;
//import org.apache.http.client.config.RequestConfig;
//import org.apache.http.client.methods.CloseableHttpResponse;
//import org.apache.http.client.methods.HttpGet;
//import org.apache.http.client.methods.HttpPost;
//import org.apache.http.client.methods.HttpRequestBase;
//import org.apache.http.client.utils.URIBuilder;
//import org.apache.http.entity.StringEntity;
//import org.apache.http.impl.client.CloseableHttpClient;
//import org.apache.http.impl.client.HttpClientBuilder;
//import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
//import org.apache.http.message.BasicNameValuePair;
//import org.apache.http.util.EntityUtils;
//import org.springframework.util.CollectionUtils;
//
//import java.io.IOException;
//import java.io.UnsupportedEncodingException;
//import java.net.URISyntaxException;
//import java.net.URLEncoder;
//import java.util.ArrayList;
//import java.util.List;
//import java.util.Map;
//
///**
// * Created by zhutao on 2016/9/3.
// */
//public class HttpUtils {
//
//    /**
//     * 设置连接的超时时间
//     */
//    private static int connectionTimeout = 1000 * 60;
//    /**
//     * 读取数据的超时时间
//     */
//    private static int soTimeout = 1000 * 60;
//    /**
//     * 设置每个路由最大连接数
//     */
//    private static int defaultMaxPerRoute = 30;
//    /**
//     * 设置最大连接数
//     */
//    private static int maxTotal = 500;
//
//    private static CloseableHttpClient httpClient;
//
//    static {
//        PoolingHttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager();
//        connectionManager.setDefaultMaxPerRoute(defaultMaxPerRoute);
//        connectionManager.setMaxTotal(maxTotal);
//        RequestConfig config = RequestConfig.custom()
//                .setConnectTimeout(connectionTimeout)
//                .setSocketTimeout(soTimeout).build();
//        httpClient = HttpClientBuilder.create().disableAutomaticRetries()
//                .setConnectionManager(connectionManager)
//                .setDefaultRequestConfig(config).build();
//    }
//
//
//    public static String executor(HttpContext httpContext) throws IOException, URISyntaxException {
//        switch (httpContext.getHttpMethod()) {
//            case POST:
//                return post(httpContext);
//            case GET:
//                return get(httpContext);
//        }
//        return null;
//    }
//
//    private static String get(HttpContext httpContext) throws URISyntaxException, IOException {
//        URIBuilder uriBuilder = getUriBuilder(httpContext);
//        HttpGet get = new HttpGet(uriBuilder.build());
//        setRequestConfig(httpContext, get);
//        if (!CollectionUtils.isEmpty(httpContext.getHeaders())) {
//            for (Map.Entry<String, String> entry : httpContext.getHeaders().entrySet()) {
//                get.setHeader(entry.getKey(), entry.getValue());
//            }
//        }
//        return getHttpString(httpContext, get);
//    }
//
//
//    private static String post(HttpContext httpContext) throws URISyntaxException, IOException {
//        URIBuilder uriBuilder = getUriBuilder(httpContext);
//        HttpPost post = new HttpPost(uriBuilder.build());
//        setRequestConfig(httpContext, post);
//        setHttpHeader(httpContext, post);
//        if (org.apache.commons.lang3.StringUtils.isNoneEmpty(httpContext.getBody())) {
//            post.setEntity(new StringEntity(httpContext.getBody(), httpContext.getCharset()));
//        }
//        return getHttpString(httpContext, post);
//    }
//
//    private static void setHttpHeader(HttpContext httpContext, HttpRequestBase httpRequest) {
//        if (!CollectionUtils.isEmpty(httpContext.getHeaders())) {
//            for (Map.Entry<String, String> entry : httpContext.getHeaders().entrySet()) {
//                httpRequest.setHeader(entry.getKey(), entry.getValue());
//            }
//        }
//    }
//
//    private static URIBuilder getUriBuilder(HttpContext httpContext) throws URISyntaxException, UnsupportedEncodingException {
//        URIBuilder uriBuilder = new URIBuilder(httpContext.getUrl());
//        if (MapUtils.isNotEmpty(httpContext.getParams())) {
//            List<NameValuePair> nvps = new ArrayList<NameValuePair>();
//            for (Map.Entry<String, String> entry : httpContext.getParams().entrySet()) {
//                NameValuePair pair = new BasicNameValuePair(entry.getKey(), URLEncoder.encode(entry.getValue(), httpContext.getCharset()));
//                nvps.add(pair);
//            }
//            uriBuilder.setParameters(nvps);
//        }
//        return uriBuilder;
//    }
//
//
//    private static String getHttpString(HttpContext httpContext, HttpRequestBase httpRequest) throws IOException {
//        CloseableHttpResponse response = httpClient.execute(httpRequest);
//        String result = null;
//        HttpEntity entity = response.getEntity();
//        if (entity != null) {
//            result = EntityUtils.toString(entity, httpContext.getCharset());
//        }
//        EntityUtils.consume(entity);
//        return result;
//    }
//
//    private static void setRequestConfig(HttpContext httpContext, HttpRequestBase httpRequest) {
//        RequestConfig.Builder build = RequestConfig.custom();
//        build.setConnectTimeout(httpContext.getTimeout())
//                .setSocketTimeout(httpContext.getTimeout());
//        if (httpContext.getTimeout() == 0) {
//            build.setConnectTimeout(connectionTimeout)
//                    .setSocketTimeout(soTimeout);
//        }
//        if (httpContext.isProxy()) {
//            //TODO 代理
//        }
//        //TODO 认证
//
//        //TODO 设置Cookie 策略
//
//        httpRequest.setConfig(build.build());
//    }
//
//
//}
