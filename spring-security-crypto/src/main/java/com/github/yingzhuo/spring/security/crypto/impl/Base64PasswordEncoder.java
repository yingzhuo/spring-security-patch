/*                 _                                            _ _                           _       _
 *  ___ _ __  _ __(_)_ __   __ _       ___  ___  ___ _   _ _ __(_) |_ _   _       _ __   __ _| |_ ___| |__
 * / __| '_ \| '__| | '_ \ / _` |_____/ __|/ _ \/ __| | | | '__| | __| | | |_____| '_ \ / _` | __/ __| '_ \
 * \__ \ |_) | |  | | | | | (_| |_____\__ \  __/ (__| |_| | |  | | |_| |_| |_____| |_) | (_| | || (__| | | |
 * |___/ .__/|_|  |_|_| |_|\__, |     |___/\___|\___|\__,_|_|  |_|\__|\__, |     | .__/ \__,_|\__\___|_| |_|
 *     |_|                 |___/                                      |___/      |_|
 *
 *  https://github.com/yingzhuo/spring-security-patch
 */
package com.github.yingzhuo.spring.security.crypto.impl;

import org.springframework.security.crypto.password.PasswordEncoder;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * @author 应卓
 * @since 1.1.1
 */
public class Base64PasswordEncoder implements PasswordEncoder {

    private final Charset charset;

    public Base64PasswordEncoder() {
        this(StandardCharsets.UTF_8);
    }

    public Base64PasswordEncoder(Charset charset) {
        this.charset = charset;
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return Base64.getUrlEncoder().encodeToString(rawPassword.toString().getBytes(charset));
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return new String(Base64.getUrlDecoder().decode(encodedPassword.getBytes(charset))).equals(rawPassword.toString());
    }

}
