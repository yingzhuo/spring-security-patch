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

import com.github.yingzhuo.spring.security.jwt.JwtToken;
import com.github.yingzhuo.spring.security.jwt.auth.AbstractJwtAuthenticationManager;
import com.github.yingzhuo.spring.security.jwt.errorhandler.JwtAuthenticationEntryPoint;
import com.github.yingzhuo.spring.security.jwt.resolver.JwtTokenResolver;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.Assert;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

/**
 * @author 应卓
 * @since 1.0.0
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenResolver tokenParser;
    private final AbstractJwtAuthenticationManager authManager;
    private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    public JwtAuthenticationFilter(JwtTokenResolver tokenParser, AbstractJwtAuthenticationManager authManager) {
        this.tokenParser = tokenParser;
        this.authManager = authManager;
    }

    @Override
    public void afterPropertiesSet() throws ServletException {
        super.afterPropertiesSet();
        Assert.notNull(tokenParser, () -> null);
        Assert.notNull(authManager, () -> null);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            doAuth(request, response);
        } catch (AuthenticationException authException) {
            if (jwtAuthenticationEntryPoint == null) {
                throw authException;
            } else {
                jwtAuthenticationEntryPoint.commence(request, response, authException);
                return;
            }
        } catch (Exception e) {
            throw e;
        }
        filterChain.doFilter(request, response);
    }

    private void doAuth(HttpServletRequest request, HttpServletResponse response) {
        Optional<JwtToken> tokenOption = tokenParser.resolve(new ServletWebRequest(request, response));

        // 所有异常全部抛出
        if (tokenOption.isPresent()) {
            UsernamePasswordAuthenticationToken upt =
                    (UsernamePasswordAuthenticationToken) authManager.authenticate(tokenOption.get());

            upt.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(upt);
        }
    }

    public void setJwtAuthenticationEntryPoint(JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint) {
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
    }

}
