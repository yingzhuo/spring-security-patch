/*                 _                                            _ _                           _       _
 *  ___ _ __  _ __(_)_ __   __ _       ___  ___  ___ _   _ _ __(_) |_ _   _       _ __   __ _| |_ ___| |__
 * / __| '_ \| '__| | '_ \ / _` |_____/ __|/ _ \/ __| | | | '__| | __| | | |_____| '_ \ / _` | __/ __| '_ \
 * \__ \ |_) | |  | | | | | (_| |_____\__ \  __/ (__| |_| | |  | | |_| |_| |_____| |_) | (_| | || (__| | | |
 * |___/ .__/|_|  |_|_| |_|\__, |     |___/\___|\___|\__,_|_|  |_|\__|\__, |     | .__/ \__,_|\__\___|_| |_|
 *     |_|                 |___/                                      |___/      |_|
 *
 *  https://github.com/yingzhuo/spring-security-patch
 */
package com.github.yingzhuo.spring.security.jwt.properties;

import com.github.yingzhuo.spring.security.common.DebugMode;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.HashSet;
import java.util.Set;

/**
 * @author 应卓
 * @since 1.1.3
 */
@ConfigurationProperties(prefix = "spring-security-patch.jwt")
public class SpringSecurityPatchJwtProperties {

    private boolean enabled = true;
    private DebugMode debugMode = DebugMode.DISABLED;
    private Set<AntPathRequestMatcher> excludes = new HashSet<>();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public DebugMode getDebugMode() {
        return debugMode;
    }

    public void setDebugMode(DebugMode debugMode) {
        this.debugMode = debugMode;
    }

    public Set<AntPathRequestMatcher> getExcludes() {
        return excludes;
    }

    public void setExcludes(Set<AntPathRequestMatcher> excludes) {
        this.excludes = excludes;
    }

}
