/*                 _                                            _ _                           _       _
 *  ___ _ __  _ __(_)_ __   __ _       ___  ___  ___ _   _ _ __(_) |_ _   _       _ __   __ _| |_ ___| |__
 * / __| '_ \| '__| | '_ \ / _` |_____/ __|/ _ \/ __| | | | '__| | __| | | |_____| '_ \ / _` | __/ __| '_ \
 * \__ \ |_) | |  | | | | | (_| |_____\__ \  __/ (__| |_| | |  | | |_| |_| |_____| |_) | (_| | || (__| | | |
 * |___/ .__/|_|  |_|_| |_|\__, |     |___/\___|\___|\__,_|_|  |_|\__|\__, |     | .__/ \__,_|\__\___|_| |_|
 *     |_|                 |___/                                      |___/      |_|
 *
 *  https://github.com/yingzhuo/spring-security-patch
 */
package com.github.yingzhuo.spring.security.jwt.resolver;

import com.github.yingzhuo.spring.security.jwt.JwtToken;
import org.springframework.util.Assert;
import org.springframework.web.context.request.NativeWebRequest;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * @author 应卓
 * @since 1.1.0
 */
public class CompositeJwtTokenResolver implements JwtTokenResolver {

    private final List<JwtTokenResolver> resolvers = new ArrayList<>();

    private CompositeJwtTokenResolver() {
    }

    public static CompositeJwtTokenResolver getInstance() {
        return new CompositeJwtTokenResolver();
    }

    @Override
    public Optional<JwtToken> resolve(NativeWebRequest request) {
        if (resolvers.isEmpty()) {
            return Optional.empty();
        }

        for (JwtTokenResolver resolver : resolvers) {
            Optional<JwtToken> op = resolver.resolve(request);
            if (op.isPresent()) return op;
        }

        return Optional.empty();
    }

    public CompositeJwtTokenResolver add(JwtTokenResolver resolver) {
        Assert.notNull(resolver, () -> null);
        return this;
    }

}
