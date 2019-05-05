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

import com.github.yingzhuo.spring.security.jwt.algorithm.SignatureAlgorithm;
import com.github.yingzhuo.spring.security.jwt.errorhandler.JwtErrorHandler;
import com.github.yingzhuo.spring.security.jwt.parser.DefaultJwtTokenParser;
import com.github.yingzhuo.spring.security.jwt.parser.JwtTokenParser;
import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.util.Assert;

/**
 * @author 应卓
 * @since 1.0.0
 */
@ConditionalOnWebApplication
@EnableConfigurationProperties(JwtCustomAutoConfig.Props.class)
public class JwtCustomAutoConfig {

    @Bean
    @ConditionalOnMissingBean
    public JwtTokenParser jwtTokenParser() {
        return new DefaultJwtTokenParser();
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtErrorHandler jwtErrorHandler() {
        return new JwtErrorHandler() {
        };
    }

    // -----------------------------------------------------------------------------------------------------------

    @Getter
    @Setter
    @ConfigurationProperties(prefix = "spring.security.jwt")
    static class Props implements InitializingBean {
        private SignatureAlgorithm algorithm = SignatureAlgorithm.HMAC512;
        private String secret = "https://github.com/yingzhuo/spring-security-patch";

        @Override
        public void afterPropertiesSet() {
            Assert.notNull(algorithm, () -> null);
            Assert.hasText(secret, () -> null);
        }
    }

}
