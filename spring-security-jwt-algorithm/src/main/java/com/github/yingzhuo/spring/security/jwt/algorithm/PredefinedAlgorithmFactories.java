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

import com.github.yingzhuo.spring.security.jwt.algorithm.ecdsa.ECDSA256AlgorithmFactory;
import com.github.yingzhuo.spring.security.jwt.algorithm.ecdsa.ECDSA384AlgorithmFactory;
import com.github.yingzhuo.spring.security.jwt.algorithm.ecdsa.ECDSA512AlgorithmFactory;
import com.github.yingzhuo.spring.security.jwt.algorithm.rsa.RSA256AlgorithmFactory;
import com.github.yingzhuo.spring.security.jwt.algorithm.rsa.RSA384AlgorithmFactory;
import com.github.yingzhuo.spring.security.jwt.algorithm.rsa.RSA512AlgorithmFactory;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.util.FileCopyUtils;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UncheckedIOException;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * @author 应卓
 * @since 1.1.3
 */
public final class PredefinedAlgorithmFactories {

    private static ResourceLoader LOADER = new DefaultResourceLoader();

    private PredefinedAlgorithmFactories() {
    }

    public static AlgorithmFactory predefinedRSA256(int number) {
        if (number < 0 || number > 7) {
            throw new IllegalArgumentException("number range: [0,7]");
        }
        return new RSA256AlgorithmFactory(
                resourceToString(String.format("classpath:com/github/yingzhuo/spring/security/jwt/algorithm/predefined/rsa-%d-public", number)),
                resourceToString(String.format("classpath:com/github/yingzhuo/spring/security/jwt/algorithm/predefined/rsa-%d-private", number))
        );
    }

    public static AlgorithmFactory predefinedRSA384(int number) {
        if (number < 0 || number > 7) {
            throw new IllegalArgumentException("number range: [0,7]");
        }
        return new RSA384AlgorithmFactory(
                resourceToString(String.format("classpath:com/github/yingzhuo/spring/security/jwt/algorithm/predefined/rsa-%d-public", number)),
                resourceToString(String.format("classpath:com/github/yingzhuo/spring/security/jwt/algorithm/predefined/rsa-%d-private", number))
        );
    }

    public static AlgorithmFactory predefinedRSA512(int number) {
        if (number < 0 || number > 7) {
            throw new IllegalArgumentException("number range: [0,7]");
        }
        return new RSA512AlgorithmFactory(
                resourceToString(String.format("classpath:com/github/yingzhuo/spring/security/jwt/algorithm/predefined/rsa-%d-public", number)),
                resourceToString(String.format("classpath:com/github/yingzhuo/spring/security/jwt/algorithm/predefined/rsa-%d-private", number))
        );
    }

    public static AlgorithmFactory predefinedECDSA256(int number) {
        if (number < 0 || number > 7) {
            throw new IllegalArgumentException("number range: [0,7]");
        }
        return new ECDSA256AlgorithmFactory(
                resourceToString(String.format("classpath:com/github/yingzhuo/spring/security/jwt/algorithm/predefined/ecdsa-%d-public", number)),
                resourceToString(String.format("classpath:com/github/yingzhuo/spring/security/jwt/algorithm/predefined/ecdsa-%d-private", number))
        );
    }

    public static AlgorithmFactory predefinedECDSA384(int number) {
        if (number < 0 || number > 7) {
            throw new IllegalArgumentException("number range: [0,7]");
        }
        return new ECDSA384AlgorithmFactory(
                resourceToString(String.format("classpath:com/github/yingzhuo/spring/security/jwt/algorithm/predefined/ecdsa-%d-public", number)),
                resourceToString(String.format("classpath:com/github/yingzhuo/spring/security/jwt/algorithm/predefined/ecdsa-%d-private", number))
        );
    }

    public static AlgorithmFactory predefinedECDSA512(int number) {
        if (number < 0 || number > 7) {
            throw new IllegalArgumentException("number range: [0,7]");
        }
        return new ECDSA512AlgorithmFactory(
                resourceToString(String.format("classpath:com/github/yingzhuo/spring/security/jwt/algorithm/predefined/ecdsa-%d-public", number)),
                resourceToString(String.format("classpath:com/github/yingzhuo/spring/security/jwt/algorithm/predefined/ecdsa-%d-private", number))
        );
    }

    private static String resourceToString(String location) {
        Resource resource = LOADER.getResource(location);
        try (Reader reader = new InputStreamReader(resource.getInputStream(), UTF_8)) {
            return FileCopyUtils.copyToString(reader);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

//    public static void main(String[] args) {
//        int number = 0;
//        String s = resourceToString(String.format("classpath:com/github/yingzhuo/spring/security/jwt/algorithm/predefined/ecdsa-%d-private", number));
//        System.out.println(s);
//    }
}
