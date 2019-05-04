/*                 _                                            _ _                           _       _
 *  ___ _ __  _ __(_)_ __   __ _       ___  ___  ___ _   _ _ __(_) |_ _   _       _ __   __ _| |_ ___| |__
 * / __| '_ \| '__| | '_ \ / _` |_____/ __|/ _ \/ __| | | | '__| | __| | | |_____| '_ \ / _` | __/ __| '_ \
 * \__ \ |_) | |  | | | | | (_| |_____\__ \  __/ (__| |_| | |  | | |_| |_| |_____| |_) | (_| | || (__| | | |
 * |___/ .__/|_|  |_|_| |_|\__, |     |___/\___|\___|\__,_|_|  |_|\__|\__, |     | .__/ \__,_|\__\___|_| |_|
 *     |_|                 |___/                                      |___/      |_|
 *
 *  https://github.com/yingzhuo/spring-security-patch
 */
package com.github.yingzhuo.spring.security.jwt.util;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;

/**
 * @author 应卓
 * @since 1.0.0
 */
@SuppressWarnings("unchecked")
public final class JwtSecurityContextUtils {

    private JwtSecurityContextUtils() {
        super();
    }

    public static Object getPrincipal() {
        try {
            return SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        } catch (Exception e) {
            return null;
        }
    }

    public static <T> T getPrincipal(Class<T> clazz) {
        return (T) getPrincipal();
    }

    public static UserDetails getUserDetails() {
        return getPrincipal(UserDetails.class);
    }

    public static Object getCredentials() {
        try {
            return SecurityContextHolder.getContext().getAuthentication().getCredentials();
        } catch (Exception e) {
            return null;
        }
    }

    public static String getCredentialsAsString() {
        return Optional.ofNullable(getCredentials()).map(Object::toString).orElse(null);
    }

}
