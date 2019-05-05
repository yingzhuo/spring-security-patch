/*                 _                                            _ _                           _       _
 *  ___ _ __  _ __(_)_ __   __ _       ___  ___  ___ _   _ _ __(_) |_ _   _       _ __   __ _| |_ ___| |__
 * / __| '_ \| '__| | '_ \ / _` |_____/ __|/ _ \/ __| | | | '__| | __| | | |_____| '_ \ / _` | __/ __| '_ \
 * \__ \ |_) | |  | | | | | (_| |_____\__ \  __/ (__| |_| | |  | | |_| |_| |_____| |_) | (_| | || (__| | | |
 * |___/ .__/|_|  |_|_| |_|\__, |     |___/\___|\___|\__,_|_|  |_|\__|\__, |     | .__/ \__,_|\__\___|_| |_|
 *     |_|                 |___/                                      |___/      |_|
 *
 *  https://github.com/yingzhuo/spring-security-patch
 */
package com.github.yingzhuo.spring.security.jwt.factory.autoconfig;

import com.github.yingzhuo.spring.security.jwt.factory.DefaultJwtTokenFactory;
import com.github.yingzhuo.spring.security.jwt.factory.JwtTokenFactory;
import com.github.yingzhuo.spring.security.jwt.factory.algorithm.SignatureAlgorithm;
import lombok.Getter;
import lombok.Setter;
import lombok.val;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.util.Assert;

/**
 * @author 应卓
 * @since 1.0.0
 */
@ConditionalOnProperty(prefix = "spring.security.jwt.factory", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(JwtFactoryAutoConfig.Props.class)
public class JwtFactoryAutoConfig {

    @Autowired
    private Props props;

    @Bean
    @ConditionalOnMissingBean
    public JwtTokenFactory jwtTokenFactory() {
        val factory = new DefaultJwtTokenFactory();
        factory.setSecret(props.getSecret());
        factory.setSignatureAlgorithm(props.algorithm);
        return factory;
    }

    @Getter
    @Setter
    @ConfigurationProperties(prefix = "spring.security.jwt")
    static class Props implements InitializingBean {
        private SignatureAlgorithm algorithm = SignatureAlgorithm.HMAC512;
        private String secret = "https://github.com/yingzhuo/spring-security-patch";
        private PropsFactory factory = new PropsFactory();

        @Override
        public void afterPropertiesSet() {
            Assert.notNull(algorithm, () -> null);
            Assert.hasText(secret, () -> null);
        }
    }

    @Getter
    @Setter
    static class PropsFactory {
        private boolean enabled = true;
    }

}
