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
import com.github.yingzhuo.spring.security.jwt.errorhandler.JwtErrorHandler;
import com.github.yingzhuo.spring.security.jwt.parser.JwtTokenParser;
import lombok.val;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

/**
 * @author 应卓
 */
public class JwtCustomHttpSecurityDSL extends AbstractHttpConfigurer<JwtCustomHttpSecurityDSL, HttpSecurity> {

    @Override
    public void configure(HttpSecurity http) throws Exception {

        // Spring's ApplicationContext
        val applicationContext = http.getSharedObject(ApplicationContext.class);

        // Token解析器
        val parser = applicationContext.getBean(JwtTokenParser.class);

        // 错误处理器
        val errorHandler = applicationContext.getBean(JwtErrorHandler.class);

        // 全局配置
        val props = applicationContext.getBean(JwtCustomAutoConfig.Props.class);

        // Jwt认证管理器
        val manager = applicationContext.getBean(AbstractJwtAuthenticationManager.class);
        manager.setSecret(props.getSecret());
        manager.setSignatureAlgorithm(props.getAlgorithm());

        // Jwt处理Filter
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(parser, manager, errorHandler);
        filter.afterPropertiesSet();

        // 设置Jwt认证过滤器
        http.addFilterBefore(filter, BasicAuthenticationFilter.class);

        // 异常处理器
        http.exceptionHandling().authenticationEntryPoint(errorHandler);
    }

}
