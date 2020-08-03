/*                 _                                            _ _                           _       _
 *  ___ _ __  _ __(_)_ __   __ _       ___  ___  ___ _   _ _ __(_) |_ _   _       _ __   __ _| |_ ___| |__
 * / __| '_ \| '__| | '_ \ / _` |_____/ __|/ _ \/ __| | | | '__| | __| | | |_____| '_ \ / _` | __/ __| '_ \
 * \__ \ |_) | |  | | | | | (_| |_____\__ \  __/ (__| |_| | |  | | |_| |_| |_____| |_) | (_| | || (__| | | |
 * |___/ .__/|_|  |_|_| |_|\__, |     |___/\___|\___|\__,_|_|  |_|\__|\__, |     | .__/ \__,_|\__\___|_| |_|
 *     |_|                 |___/                                      |___/      |_|
 *
 *  https://github.com/yingzhuo/spring-security-patch
 */
package com.github.yingzhuo.spring.security.crypto;

import com.github.yingzhuo.spring.security.crypto.impl.Base64PasswordEncoder;
import com.github.yingzhuo.spring.security.crypto.impl.ReversePasswordEncoder;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.*;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

import java.util.HashMap;
import java.util.Map;

/**
 * @author 应卓
 * @since 1.1.1
 */
public final class PasswordEncoderFactories {

    public static final String bcrypt = "bcrypt";
    public static final String ldap = "ldap";
    public static final String md4 = "MD4";
    public static final String md5 = "MD5";
    public static final String noop = "noop";
    public static final String pbkdf2 = "pbkdf2";
    public static final String scrypt = "scrypt";
    public static final String sha1 = "SHA-1";
    public static final String sha256 = "SHA-256";
    public static final String argon2 = "argon2";
    public static final String base64 = "base64";
    public static final String reverse = "reverse";

    private PasswordEncoderFactories() {
    }

    public static PasswordEncoder create() {
        return create(bcrypt);
    }

    @SuppressWarnings("deprecation")
    public static PasswordEncoder create(String encodingId) {
        final Map<String, PasswordEncoder> encoders = new HashMap<>();
        encoders.put(bcrypt, new BCryptPasswordEncoder());
        encoders.put(ldap, new LdapShaPasswordEncoder());
        encoders.put(md4, new Md4PasswordEncoder());
        encoders.put(md5, new MessageDigestPasswordEncoder("MD5"));
        encoders.put(noop, NoOpPasswordEncoder.getInstance());
        encoders.put(pbkdf2, new Pbkdf2PasswordEncoder());
        encoders.put(scrypt, new SCryptPasswordEncoder());
        encoders.put(sha1, new MessageDigestPasswordEncoder("SHA-1"));
        encoders.put(sha256, new MessageDigestPasswordEncoder("SHA-256"));
        encoders.put(argon2, new Argon2PasswordEncoder());
        encoders.put(base64, new Base64PasswordEncoder());
        encoders.put(reverse, new ReversePasswordEncoder());
        return new DelegatingPasswordEncoder(encodingId, encoders);
    }

}
