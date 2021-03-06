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

import com.github.yingzhuo.spring.security.jwt.algorithm.AlgorithmFactories;
import com.github.yingzhuo.spring.security.jwt.algorithm.AlgorithmFactory;
import com.github.yingzhuo.spring.security.jwt.factory.JwtTokenFactory;
import com.github.yingzhuo.spring.security.jwt.factory.JwtTokenFactoryImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

/**
 * @author 应卓
 * @since 1.0.0
 */
public class JwtFactoryAutoConfig {

    @Autowired(required = false)
    private AlgorithmFactory algorithmFactory = AlgorithmFactories.getDefault();

    @Bean
    @ConditionalOnMissingBean
    public JwtTokenFactory jwtTokenFactory() {
        return new JwtTokenFactoryImpl(algorithmFactory);
    }

}
