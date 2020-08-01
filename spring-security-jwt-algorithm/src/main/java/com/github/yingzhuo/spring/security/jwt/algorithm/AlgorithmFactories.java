/*                 _                                            _ _                           _       _
 *  ___ _ __  _ __(_)_ __   __ _       ___  ___  ___ _   _ _ __(_) |_ _   _       _ __   __ _| |_ ___| |__
 * / __| '_ \| '__| | '_ \ / _` |_____/ __|/ _ \/ __| | | | '__| | __| | | |_____| '_ \ / _` | __/ __| '_ \
 * \__ \ |_) | |  | | | | | (_| |_____\__ \  __/ (__| |_| | |  | | |_| |_| |_____| |_) | (_| | || (__| | | |
 * |___/ .__/|_|  |_|_| |_|\__, |     |___/\___|\___|\__,_|_|  |_|\__|\__, |     | .__/ \__,_|\__\___|_| |_|
 *     |_|                 |___/                                      |___/      |_|
 *
 *  https://github.com/yingzhuo/spring-security-patch
 */
package com.github.yingzhuo.spring.security.jwt.algorithm;

import com.auth0.jwt.algorithms.Algorithm;
import com.github.yingzhuo.spring.security.jwt.algorithm.ecdsa.ECDSA256AlgorithmFactory;
import com.github.yingzhuo.spring.security.jwt.algorithm.ecdsa.ECDSA384AlgorithmFactory;
import com.github.yingzhuo.spring.security.jwt.algorithm.ecdsa.ECDSA512AlgorithmFactory;
import com.github.yingzhuo.spring.security.jwt.algorithm.rsa.RSA256AlgorithmFactory;
import com.github.yingzhuo.spring.security.jwt.algorithm.rsa.RSA384AlgorithmFactory;
import com.github.yingzhuo.spring.security.jwt.algorithm.rsa.RSA512AlgorithmFactory;

/**
 * @author 应卓
 * @since 1.1.0
 */
public final class AlgorithmFactories {

    private AlgorithmFactories() {
    }

    public static AlgorithmFactory getDefault() {
        return hmac512(AlgorithmFactories.class.getName());
    }

    public static AlgorithmFactory none() {
        return Algorithm::none;
    }

    public static AlgorithmFactory hmac256(String secret) {
        return () -> Algorithm.HMAC256(secret);
    }

    public static AlgorithmFactory hmac384(String secret) {
        return () -> Algorithm.HMAC384(secret);
    }

    public static AlgorithmFactory hmac512(String secret) {
        return () -> Algorithm.HMAC512(secret);
    }

    public static AlgorithmFactory rsa256(String publicKey, String privateKey) {
        return new RSA256AlgorithmFactory(publicKey, privateKey);
    }

    public static AlgorithmFactory rsa384(String publicKey, String privateKey) {
        return new RSA384AlgorithmFactory(publicKey, privateKey);
    }

    public static AlgorithmFactory rsa512(String publicKey, String privateKey) {
        return new RSA512AlgorithmFactory(publicKey, privateKey);
    }

    public static AlgorithmFactory ecdsa256(String publicKey, String privateKey) {
        return new ECDSA256AlgorithmFactory(publicKey, privateKey);
    }

    public static AlgorithmFactory ecdsa384(String publicKey, String privateKey) {
        return new ECDSA384AlgorithmFactory(publicKey, privateKey);
    }

    public static AlgorithmFactory ecdsa512(String publicKey, String privateKey) {
        return new ECDSA512AlgorithmFactory(publicKey, privateKey);
    }

}
