package com.smile.core.json;

import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.serializer.SerializerFeature;
import com.alibaba.fastjson.support.config.FastJsonConfig;
import com.alibaba.fastjson.support.spring.FastJsonHttpMessageConverter;

import com.alibaba.fastjson.support.spring.FastJsonpHttpMessageConverter4;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.nio.charset.Charset;


@Configuration
@ConditionalOnClass({FastJsonHttpMessageConverter.class}) //1
@ConditionalOnProperty(
        name = {"spring.http.converters.preferred-json-mapper"},
        havingValue = "fastjson",
        matchIfMissing = true
)
public class FastJson2HttpMessageConverterConfiguration {
    protected FastJson2HttpMessageConverterConfiguration() {
    }

    @Bean
    @ConditionalOnMissingBean({FastJsonHttpMessageConverter.class})//3
    public FastJsonpHttpMessageConverter4 fastJsonHttpMessageConverter() {
        FastJsonpHttpMessageConverter4 converter = new FastJsonpHttpMessageConverter4();
        FastJsonConfig fastJsonConfig = new FastJsonConfig();//4
        fastJsonConfig.setSerializerFeatures(
                SerializerFeature.PrettyFormat,
                SerializerFeature.WriteClassName,
                SerializerFeature.WriteMapNullValue
        );
        fastJsonConfig.setCharset(Charset.forName("utf-8"));
        fastJsonConfig.setDateFormat("yyyy-MM-dd HH:mm:ss");
        fastJsonConfig.setFeatures(Feature.SupportArrayToBean,Feature.UseBigDecimal);
        converter.setFastJsonConfig(fastJsonConfig);
        return converter;
    }
}