/*                 _                                            _ _                           _       _
 *  ___ _ __  _ __(_)_ __   __ _       ___  ___  ___ _   _ _ __(_) |_ _   _       _ __   __ _| |_ ___| |__
 * / __| '_ \| '__| | '_ \ / _` |_____/ __|/ _ \/ __| | | | '__| | __| | | |_____| '_ \ / _` | __/ __| '_ \
 * \__ \ |_) | |  | | | | | (_| |_____\__ \  __/ (__| |_| | |  | | |_| |_| |_____| |_) | (_| | || (__| | | |
 * |___/ .__/|_|  |_|_| |_|\__, |     |___/\___|\___|\__,_|_|  |_|\__|\__, |     | .__/ \__,_|\__\___|_| |_|
 *     |_|                 |___/                                      |___/      |_|
 *
 *  https://github.com/yingzhuo/spring-security-patch
 */
package com.github.yingzhuo.spring.security.jwt.parser;

import com.github.yingzhuo.spring.security.jwt.JwtToken;
import org.springframework.web.context.request.NativeWebRequest;

import java.util.Optional;

/**
 * @author 应卓
 * @since 1.0.0
 */
public class DefaultJwtTokenParser implements JwtTokenParser {

    private static final String AUTHORIZATION = "Authorization";
    private static final String BEARER = "Bearer ";
    private static final int BEARER_LEN = BEARER.length();

    @Override
    public Optional<JwtToken> parse(NativeWebRequest request) {

        final String headerValue = request.getHeader(AUTHORIZATION);

        if (headerValue == null) {
            return Optional.empty();
        }

        if (!headerValue.startsWith(BEARER)) {
            return Optional.empty();
        }

        String rawToken = headerValue.substring(BEARER_LEN);

        return Optional.of(
                JwtToken.of(rawToken)
        );
    }

}
