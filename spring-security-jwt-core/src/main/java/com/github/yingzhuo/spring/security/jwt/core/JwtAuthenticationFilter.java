/*                 _                                            _ _                           _       _
 *  ___ _ __  _ __(_)_ __   __ _       ___  ___  ___ _   _ _ __(_) |_ _   _       _ __   __ _| |_ ___| |__
 * / __| '_ \| '__| | '_ \ / _` |_____/ __|/ _ \/ __| | | | '__| | __| | | |_____| '_ \ / _` | __/ __| '_ \
 * \__ \ |_) | |  | | | | | (_| |_____\__ \  __/ (__| |_| | |  | | |_| |_| |_____| |_) | (_| | || (__| | | |
 * |___/ .__/|_|  |_|_| |_|\__, |     |___/\___|\___|\__,_|_|  |_|\__|\__, |     | .__/ \__,_|\__\___|_| |_|
 *     |_|                 |___/                                      |___/      |_|
 *
 *  https://github.com/yingzhuo/spring-security-patch
 */
package com.github.yingzhuo.spring.security.jwt.core;

import com.github.yingzhuo.spring.security.common.DebugMode;
import com.github.yingzhuo.spring.security.common.Debugger;
import com.github.yingzhuo.spring.security.jwt.JwtToken;
import com.github.yingzhuo.spring.security.jwt.auth.AbstractJwtAuthenticationManager;
import com.github.yingzhuo.spring.security.jwt.errorhandler.JwtAuthenticationEntryPoint;
import com.github.yingzhuo.spring.security.jwt.resolver.JwtTokenResolver;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import java.util.Set;

/**
 * @author 应卓
 * @since 1.0.0
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenResolver tokenResolver;
    private final AbstractJwtAuthenticationManager authManager;
    private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private Set<AntPathRequestMatcher> excludes;
    private DebugMode debugMode = DebugMode.DISABLED;
    private Debugger debugger;

    public JwtAuthenticationFilter(JwtTokenResolver tokenResolver, AbstractJwtAuthenticationManager authManager) {
        this.tokenResolver = tokenResolver;
        this.authManager = authManager;
    }

    @Override
    public void afterPropertiesSet() throws ServletException {
        super.afterPropertiesSet();
        Assert.notNull(tokenResolver, () -> null);
        Assert.notNull(authManager, () -> null);
        this.debugger = Debugger.of(LoggerFactory.getLogger(JwtAuthenticationFilter.class), debugMode);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        final String path = request.getRequestURI();
        final String method = request.getMethod().toUpperCase();

        if (excludes != null) {
            for (AntPathRequestMatcher matcher : excludes) {
                if (matcher.matches(request)) {
                    debugger.debug("[{}][{}] 已跳过", path, method);
                    filterChain.doFilter(request, response);
                    return;
                }
            }
        }

        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            debugger.debug("[{}][{}] 已经通过认证", path, method);
            filterChain.doFilter(request, response);
            return;
        }

        try {
            debugger.debug("[{}][{}] 认证开始", path, method);
            doAuth(request, response);
            debugger.debug("[{}][{}] 认证结束", path, method);
        } catch (AuthenticationException authException) {
            if (jwtAuthenticationEntryPoint == null) {
                debugger.debug("[{}][{}] 抛出认证异常: {}", path, method, authException.getClass().getName());
                throw authException;
            } else {
                debugger.debug("[{}][{}] 处理认证异常: {}", path, method, authException.getClass().getName());
                jwtAuthenticationEntryPoint.commence(request, response, authException);
                return;
            }
        } catch (Exception e) {
            debugger.debug("[{}][{}] 抛出其他异常: {}", path, method, e.getClass().getName());
            throw e;
        }

        filterChain.doFilter(request, response);
    }

    private void doAuth(HttpServletRequest request, HttpServletResponse response) {
        Optional<JwtToken> tokenOption = tokenResolver.resolve(new ServletWebRequest(request, response));

        // 所有异常全部抛出
        if (tokenOption.isPresent()) {
            UsernamePasswordAuthenticationToken upt =
                    (UsernamePasswordAuthenticationToken) authManager.authenticate(tokenOption.get());

            upt.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(upt);
        }
    }

    public void setDebugMode(DebugMode debugMode) {
        this.debugMode = debugMode;
    }

    public void setJwtAuthenticationEntryPoint(JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint) {
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
    }

    public void setExcludes(Set<AntPathRequestMatcher> excludes) {
        this.excludes = excludes;
    }

}
