/*                 _                                            _ _                           _       _
 *  ___ _ __  _ __(_)_ __   __ _       ___  ___  ___ _   _ _ __(_) |_ _   _       _ __   __ _| |_ ___| |__
 * / __| '_ \| '__| | '_ \ / _` |_____/ __|/ _ \/ __| | | | '__| | __| | | |_____| '_ \ / _` | __/ __| '_ \
 * \__ \ |_) | |  | | | | | (_| |_____\__ \  __/ (__| |_| | |  | | |_| |_| |_____| |_) | (_| | || (__| | | |
 * |___/ .__/|_|  |_|_| |_|\__, |     |___/\___|\___|\__,_|_|  |_|\__|\__, |     | .__/ \__,_|\__\___|_| |_|
 *     |_|                 |___/                                      |___/      |_|
 *
 *  https://github.com/yingzhuo/spring-security-patch
 */
package com.github.yingzhuo.spring.security.jwt.dsl;

import com.github.yingzhuo.spring.security.jwt.auth.AbstractJwtAuthenticationManager;
import com.github.yingzhuo.spring.security.jwt.core.JwtAuthenticationFilter;
import com.github.yingzhuo.spring.security.jwt.errorhandler.JwtAuthenticationEntryPoint;
import com.github.yingzhuo.spring.security.jwt.properties.SpringSecurityPatchJwtProperties;
import com.github.yingzhuo.spring.security.jwt.resolver.JwtTokenResolver;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

/**
 * @author 应卓
 * @since 1.0.0
 */
public class JwtCustomHttpSecurityDSL extends AbstractHttpConfigurer<JwtCustomHttpSecurityDSL, HttpSecurity> {

    @Override
    public void configure(HttpSecurity http) throws Exception {

        final ApplicationContext ac = http.getSharedObject(ApplicationContext.class);

        final SpringSecurityPatchJwtProperties properties = getBean(ac, SpringSecurityPatchJwtProperties.class, null);
        if (properties == null || !properties.isEnabled()) {
            return;
        }

        // Token解析器
        final JwtTokenResolver resolver = getBean(ac, JwtTokenResolver.class, JwtTokenResolver.getDefault());

        // Jwt认证管理器
        final AbstractJwtAuthenticationManager manager = getBean(ac, AbstractJwtAuthenticationManager.class, null);
        if (manager == null) {
            throw new NoSuchBeanDefinitionException(AbstractJwtAuthenticationManager.class);
        }

        // Jwt处理Filter
        final JwtAuthenticationFilter filter = new JwtAuthenticationFilter(resolver, manager);
        filter.setJwtAuthenticationEntryPoint(getBean(ac, JwtAuthenticationEntryPoint.class, null));
        filter.afterPropertiesSet();

        // 设置Jwt认证过滤器
        http.addFilterAfter(filter, BasicAuthenticationFilter.class);
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
