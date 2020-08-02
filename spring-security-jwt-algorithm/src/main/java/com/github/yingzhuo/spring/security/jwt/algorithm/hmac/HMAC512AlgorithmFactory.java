/*                 _                                            _ _                           _       _
 *  ___ _ __  _ __(_)_ __   __ _       ___  ___  ___ _   _ _ __(_) |_ _   _       _ __   __ _| |_ ___| |__
 * / __| '_ \| '__| | '_ \ / _` |_____/ __|/ _ \/ __| | | | '__| | __| | | |_____| '_ \ / _` | __/ __| '_ \
 * \__ \ |_) | |  | | | | | (_| |_____\__ \  __/ (__| |_| | |  | | |_| |_| |_____| |_) | (_| | || (__| | | |
 * |___/ .__/|_|  |_|_| |_|\__, |     |___/\___|\___|\__,_|_|  |_|\__|\__, |     | .__/ \__,_|\__\___|_| |_|
 *     |_|                 |___/                                      |___/      |_|
 *
 *  https://github.com/yingzhuo/spring-security-patch
 */
package com.github.yingzhuo.spring.security.jwt.algorithm.hmac;

import com.auth0.jwt.algorithms.Algorithm;
import com.github.yingzhuo.spring.security.jwt.algorithm.AlgorithmFactory;

/**
 * @author 应卓
 * @since 1.1.1
 */
public class HMAC512AlgorithmFactory implements AlgorithmFactory {

    private final String secret;

    public HMAC512AlgorithmFactory(String secret) {
        this.secret = secret;
    }

    @Override
    public Algorithm create() {
        return Algorithm.HMAC512(secret);
    }

}
