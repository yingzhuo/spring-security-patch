/*                 _                                            _ _                           _       _
 *  ___ _ __  _ __(_)_ __   __ _       ___  ___  ___ _   _ _ __(_) |_ _   _       _ __   __ _| |_ ___| |__
 * / __| '_ \| '__| | '_ \ / _` |_____/ __|/ _ \/ __| | | | '__| | __| | | |_____| '_ \ / _` | __/ __| '_ \
 * \__ \ |_) | |  | | | | | (_| |_____\__ \  __/ (__| |_| | |  | | |_| |_| |_____| |_) | (_| | || (__| | | |
 * |___/ .__/|_|  |_|_| |_|\__, |     |___/\___|\___|\__,_|_|  |_|\__|\__, |     | .__/ \__,_|\__\___|_| |_|
 *     |_|                 |___/                                      |___/      |_|
 *
 *  https://github.com/yingzhuo/spring-security-patch
 */
package com.github.yingzhuo.spring.security.jwt.factory;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.github.yingzhuo.spring.security.jwt.algorithm.AlgorithmFactory;

import java.util.Date;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * @author 应卓
 * @since 1.1.0
 */
public class JwtTokenFactoryImpl implements JwtTokenFactory {

    private final Algorithm alg;

    public JwtTokenFactoryImpl(AlgorithmFactory algorithmFactory) {
        this.alg = algorithmFactory.create();
    }

    @Override
    public String create(JwtTokenMetadata metadata) {
        Objects.requireNonNull(metadata);

        final JWTCreator.Builder builder = JWT.create();

        // Public Claims (Public)
        Optional.ofNullable(metadata.getKeyId()).ifPresent(builder::withKeyId);

        // Public Claims (Payload)
        Optional.ofNullable(metadata.getIssuer()).ifPresent(builder::withIssuer);
        Optional.ofNullable(metadata.getSubject()).ifPresent(builder::withSubject);
        Optional.ofNullable(metadata.getExpiresAt()).ifPresent(builder::withExpiresAt);
        Optional.ofNullable(metadata.getNotBefore()).ifPresent(builder::withNotBefore);
        Optional.ofNullable(metadata.getIssuedAt()).ifPresent(builder::withIssuedAt);
        Optional.ofNullable(metadata.getJwtId()).ifPresent(builder::withJWTId);
        Optional.ofNullable(metadata.getAudience()).ifPresent(it -> {
            if (!it.isEmpty()) {
                builder.withAudience(metadata.getAudience().toArray(new String[0]));
            }
        });

        // Private Claims
        Optional.ofNullable(metadata.getPrivateClaims()).ifPresent(map -> {
            final Set<String> keySet = map.keySet();
            for (String name : keySet) {
                Object value = map.get(name);

                if (value instanceof String) {
                    builder.withClaim(name, (String) value);
                    continue;
                }

                if (value instanceof Integer) {
                    builder.withClaim(name, (Integer) value);
                    continue;
                }

                if (value instanceof Boolean) {
                    builder.withClaim(name, (Boolean) value);
                    continue;
                }

                if (value instanceof Date) {
                    builder.withClaim(name, (Date) value);
                    continue;
                }

                if (value instanceof Long) {
                    builder.withClaim(name, (Long) value);
                    continue;
                }

                if (value instanceof Double) {
                    builder.withClaim(name, (Double) value);
                    continue;
                }

                if (value instanceof String[]) {
                    builder.withArrayClaim(name, (String[]) value);
                    continue;
                }

                if (value instanceof Integer[]) {
                    builder.withArrayClaim(name, (Integer[]) value);
                    continue;
                }

                if (value instanceof Long[]) {
                    builder.withArrayClaim(name, (Long[]) value);
                }
            }
        });

        return builder.sign(alg);
    }

}
