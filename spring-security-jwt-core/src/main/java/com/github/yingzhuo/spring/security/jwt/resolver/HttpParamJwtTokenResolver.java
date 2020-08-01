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
import org.springframework.web.context.request.NativeWebRequest;

import java.util.Optional;

/**
 * @author 应卓
 * @since 1.1.0
 */
public class HttpParamJwtTokenResolver implements JwtTokenResolver {

    private final String paramName;
    private final String prefix;
    private final int prefixLen;

    public HttpParamJwtTokenResolver(String paramName, String prefix) {
        this.paramName = paramName;
        this.prefix = prefix;
        this.prefixLen = prefix.length();
    }

    @Override
    public Optional<JwtToken> resolve(NativeWebRequest request) {
        final String paramValue = request.getParameter(paramName);

        if (paramValue == null ||
                !paramValue.startsWith(prefix) ||
                paramValue.split("\\.").length != 3) {
            return Optional.empty();
        }

        return Optional.of(JwtToken.of(paramValue.substring(prefixLen)));
    }

}
