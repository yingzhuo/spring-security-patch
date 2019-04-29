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
import com.github.yingzhuo.spring.security.jwt.factory.algorithm.SignatureAlgorithm;
import com.github.yingzhuo.spring.security.jwt.factory.algorithm.SignatureAlgorithmUtils;

import java.util.Date;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * @author 应卓
 */
public class DefaultJwtTokenFactory implements JwtTokenFactory {

    private String secret;
    private SignatureAlgorithm signatureAlgorithm;

    public DefaultJwtTokenFactory() {
        super();
    }

    @Override
    public String create(JwtTokenInfo info) {
        Objects.requireNonNull(info);

        JWTCreator.Builder builder = JWT.create();

        // Public Claims (Public)
        Optional.ofNullable(info.getKeyId()).ifPresent(builder::withKeyId);

        // Public Claims (Payload)
        Optional.ofNullable(info.getIssuer()).ifPresent(builder::withIssuer);
        Optional.ofNullable(info.getSubject()).ifPresent(builder::withSubject);
        Optional.ofNullable(info.getExpiresAt()).ifPresent(builder::withExpiresAt);
        Optional.ofNullable(info.getNotBefore()).ifPresent(builder::withNotBefore);
        Optional.ofNullable(info.getIssuedAt()).ifPresent(builder::withIssuedAt);
        Optional.ofNullable(info.getJwtId()).ifPresent(builder::withJWTId);
        Optional.ofNullable(info.getAudience()).ifPresent(it -> {
            if (!it.isEmpty()) {
                builder.withAudience(info.getAudience().toArray(new String[info.getAudience().size()]));
            }
        });

        // Private Claims
        Optional.ofNullable(info.getPrivateClaims()).ifPresent(map -> {
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
//                    continue;
                }
            }
        });

        return builder.sign(SignatureAlgorithmUtils.toAlgorithm(signatureAlgorithm, secret));
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public void setSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

}
