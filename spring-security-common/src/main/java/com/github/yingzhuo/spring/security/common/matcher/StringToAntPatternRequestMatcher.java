/*                 _                                            _ _                           _       _
 *  ___ _ __  _ __(_)_ __   __ _       ___  ___  ___ _   _ _ __(_) |_ _   _       _ __   __ _| |_ ___| |__
 * / __| '_ \| '__| | '_ \ / _` |_____/ __|/ _ \/ __| | | | '__| | __| | | |_____| '_ \ / _` | __/ __| '_ \
 * \__ \ |_) | |  | | | | | (_| |_____\__ \  __/ (__| |_| | |  | | |_| |_| |_____| |_) | (_| | || (__| | | |
 * |___/ .__/|_|  |_|_| |_|\__, |     |___/\___|\___|\__,_|_|  |_|\__|\__, |     | .__/ \__,_|\__\___|_| |_|
 *     |_|                 |___/                                      |___/      |_|
 *
 *  https://github.com/yingzhuo/spring-security-patch
 */
package com.github.yingzhuo.spring.security.common.matcher;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * @author 应卓
 * @since 1.1.3
 */
public class StringToAntPatternRequestMatcher implements Converter<String, AntPathRequestMatcher> {

    @Override
    public AntPathRequestMatcher convert(String value) {

        String[] parts = value.split("[ ,]+", 2);

        if (parts.length == 2) {
            String method = parts[0].toUpperCase().trim();
            String pattern = parts[1].trim();
            return new AntPathRequestMatcher(pattern, method);
        } else {
            return new AntPathRequestMatcher(parts[0]);
        }
    }

}
