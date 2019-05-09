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

import com.github.yingzhuo.spring.security.jwt.AbstractJwtAuthenticationManager;
import com.github.yingzhuo.spring.security.jwt.JwtAuthenticationFilter;
import com.github.yingzhuo.spring.security.jwt.errorhandler.JwtAuthenticationEntryPoint;
import com.github.yingzhuo.spring.security.jwt.parser.DefaultJwtTokenParser;
import com.github.yingzhuo.spring.security.jwt.parser.JwtTokenParser;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

/**
 * @author 应卓
 * @since 1.0.0
 */
@Slf4j
public class JwtCustomHttpSecurityDSL extends AbstractHttpConfigurer<JwtCustomHttpSecurityDSL, HttpSecurity> {

    @Override
    public void configure(HttpSecurity http) throws Exception {

        val ac = http.getSharedObject(ApplicationContext.class);

        // 全局配置
        val props = ac.getBean(JwtCustomAutoConfig.Props.class);

        if (!props.isDslEnabled()) {
            return;
        }

        // Token解析器
        val parser = getBean(ac, JwtTokenParser.class, new DefaultJwtTokenParser());

        // 错误处理器
        val authenticationEntryPoint = getBean(ac, AuthenticationEntryPoint.class, new JwtAuthenticationEntryPoint());

        // Jwt认证管理器
        val manager = getBean(ac, AbstractJwtAuthenticationManager.class, null);
        if (manager == null) {
            throw new NoSuchBeanDefinitionException(AbstractJwtAuthenticationManager.class);
        }

        manager.setSecret(props.getSecret());
        manager.setSignatureAlgorithm(props.getAlgorithm());

        // Jwt处理Filter
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(parser, manager, authenticationEntryPoint);
        filter.afterPropertiesSet();

        // 设置Jwt认证过滤器
        http.addFilterBefore(filter, BasicAuthenticationFilter.class);
    }

    private <T> T getBean(ApplicationContext ac, Class<T> beanType, T defaultIfNotFound) {
        try {
            return ac.getBean(beanType);
        } catch (NoUniqueBeanDefinitionException e) {
            log.error(e.getMessage(), e);
            throw e;
        } catch (NoSuchBeanDefinitionException e) {
            return defaultIfNotFound;
        }
    }

}
