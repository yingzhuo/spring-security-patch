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
import org.springframework.http.HttpHeaders;
import org.springframework.web.context.request.NativeWebRequest;

import java.util.Optional;

/**
 * @author 应卓
 * @since 1.1.0
 */
public class HttpHeaderJwtTokenResolver implements JwtTokenResolver {

    private final String headerName;
    private final String prefix;
    private final int prefixLen;

    public HttpHeaderJwtTokenResolver() {
        this(HttpHeaders.AUTHORIZATION, "Bearer ");
    }

    public HttpHeaderJwtTokenResolver(String headerName, String prefix) {
        this.headerName = headerName;
        this.prefix = prefix;
        this.prefixLen = prefix.length();
    }

    @Override
    public Optional<JwtToken> resolve(NativeWebRequest request) {

        String headerValue = request.getHeader(headerName);

        if (headerValue == null || !headerValue.startsWith(prefix)) {
            return Optional.empty();
        }

        headerValue = headerValue.substring(prefixLen);

        if (headerValue.split("\\.").length == 2 && !headerValue.endsWith(".")) {
            headerValue += ".";
        }

        return Optional.of(JwtToken.of(headerValue));
    }

}
