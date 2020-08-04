/*                 _                                            _ _                           _       _
 *  ___ _ __  _ __(_)_ __   __ _       ___  ___  ___ _   _ _ __(_) |_ _   _       _ __   __ _| |_ ___| |__
 * / __| '_ \| '__| | '_ \ / _` |_____/ __|/ _ \/ __| | | | '__| | __| | | |_____| '_ \ / _` | __/ __| '_ \
 * \__ \ |_) | |  | | | | | (_| |_____\__ \  __/ (__| |_| | |  | | |_| |_| |_____| |_) | (_| | || (__| | | |
 * |___/ .__/|_|  |_|_| |_|\__, |     |___/\___|\___|\__,_|_|  |_|\__|\__, |     | .__/ \__,_|\__\___|_| |_|
 *     |_|                 |___/                                      |___/      |_|
 *
 *  https://github.com/yingzhuo/spring-security-patch
 */
package com.github.yingzhuo.spring.security.param.dsl;

import com.github.yingzhuo.spring.security.param.core.ParamsContextValidationFilter;
import com.github.yingzhuo.spring.security.param.properties.SpringSecurityPatchParamsProperties;
import com.github.yingzhuo.spring.security.param.resolver.DefaultParamsContextResolver;
import com.github.yingzhuo.spring.security.param.resolver.ParamsContextResolver;
import com.github.yingzhuo.spring.security.param.validation.DefaultParamsValidationAlgorithm;
import com.github.yingzhuo.spring.security.param.validation.ParamsValidationAlgorithm;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.header.HeaderWriterFilter;

/**
 * @author 应卓
 * @since 1.1.3
 */
public class ParamsValidationHttpSecurityDSL extends AbstractHttpConfigurer<ParamsValidationHttpSecurityDSL, HttpSecurity> {

    @Override
    public void configure(HttpSecurity http) throws Exception {

        final ApplicationContext ac = http.getSharedObject(ApplicationContext.class);

        final SpringSecurityPatchParamsProperties properties = getBean(ac, SpringSecurityPatchParamsProperties.class, null);
        if (properties == null || !properties.isEnabled()) {
            return;
        }

        final ParamsContextResolver resolver = getBean(ac, ParamsContextResolver.class, new DefaultParamsContextResolver());
        final ParamsValidationAlgorithm algorithm = getBean(ac, ParamsValidationAlgorithm.class, new DefaultParamsValidationAlgorithm());

        final ParamsContextValidationFilter filter = new ParamsContextValidationFilter();
        filter.setDebugMode(properties.getDebugMode());
        filter.setMaxDiff(properties.getTimestamp().getMaxDiff());
        filter.setParamsContextResolver(resolver);
        filter.setParamsValidationAlgorithm(algorithm);
        filter.afterPropertiesSet();

        http.addFilterAfter(filter, HeaderWriterFilter.class);
    }

    private <T> T getBean(ApplicationContext ac, Class<T> beanType, T defaultIfNotFound) {
        try {
            return ac.getBean(beanType);
        } catch (NoUniqueBeanDefinitionException e) {
            throw e;
        } catch (NoSuchBeanDefinitionException e) {
            return defaultIfNotFound;
        }
    }

}
