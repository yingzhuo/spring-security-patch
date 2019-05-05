/*                 _                                            _ _                           _       _
 *  ___ _ __  _ __(_)_ __   __ _       ___  ___  ___ _   _ _ __(_) |_ _   _       _ __   __ _| |_ ___| |__
 * / __| '_ \| '__| | '_ \ / _` |_____/ __|/ _ \/ __| | | | '__| | __| | | |_____| '_ \ / _` | __/ __| '_ \
 * \__ \ |_) | |  | | | | | (_| |_____\__ \  __/ (__| |_| | |  | | |_| |_| |_____| |_) | (_| | || (__| | | |
 * |___/ .__/|_|  |_|_| |_|\__, |     |___/\___|\___|\__,_|_|  |_|\__|\__, |     | .__/ \__,_|\__\___|_| |_|
 *     |_|                 |___/                                      |___/      |_|
 *
 *  https://github.com/yingzhuo/spring-security-patch
 */
package com.github.yingzhuo.spring.security.jwt.factory.algorithm;

import com.auth0.jwt.algorithms.Algorithm;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

/**
 * @author 应卓
 * @since 1.0.0
 */
public enum SignatureAlgorithm {

    // 其他算法暂不支持

    HMAC256,

    HMAC384,

    HMAC512,

    RSA256,

    RSA384,

    RSA512;

    @SuppressWarnings("Duplicates")
    public static Algorithm gen(SignatureAlgorithm signatureAlgorithm, String secret) {
        Objects.requireNonNull(secret);
        Objects.requireNonNull(signatureAlgorithm);

        KeyPairGenerator generator;
        KeyPair keyPair;
        RSAPublicKey publicKey;
        RSAPrivateKey privateKey;

        try {
            switch (signatureAlgorithm) {
                case HMAC256:
                    return Algorithm.HMAC256(secret);
                case HMAC384:
                    return Algorithm.HMAC384(secret);
                case HMAC512:
                    return Algorithm.HMAC512(secret);
                case RSA256:
                    generator = KeyPairGenerator.getInstance("RSA");
                    generator.initialize(1024);
                    keyPair = generator.generateKeyPair();
                    publicKey = (RSAPublicKey) keyPair.getPublic();
                    privateKey = (RSAPrivateKey) keyPair.getPrivate();
                    return Algorithm.RSA256(publicKey, privateKey);
                case RSA384:
                    generator = KeyPairGenerator.getInstance("RSA");
                    generator.initialize(1024);
                    keyPair = generator.generateKeyPair();
                    publicKey = (RSAPublicKey) keyPair.getPublic();
                    privateKey = (RSAPrivateKey) keyPair.getPrivate();
                    return Algorithm.RSA384(publicKey, privateKey);
                case RSA512:
                    generator = KeyPairGenerator.getInstance("RSA");
                    generator.initialize(1024);
                    keyPair = generator.generateKeyPair();
                    publicKey = (RSAPublicKey) keyPair.getPublic();
                    privateKey = (RSAPrivateKey) keyPair.getPrivate();
                    return Algorithm.RSA512(publicKey, privateKey);
                default:
                    throw new IllegalArgumentException();
            }
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException();
        }
    }

}
