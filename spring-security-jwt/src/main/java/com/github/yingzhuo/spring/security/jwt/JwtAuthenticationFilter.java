/*                 _                                            _ _                           _       _
 *  ___ _ __  _ __(_)_ __   __ _       ___  ___  ___ _   _ _ __(_) |_ _   _       _ __   __ _| |_ ___| |__
 * / __| '_ \| '__| | '_ \ / _` |_____/ __|/ _ \/ __| | | | '__| | __| | | |_____| '_ \ / _` | __/ __| '_ \
 * \__ \ |_) | |  | | | | | (_| |_____\__ \  __/ (__| |_| | |  | | |_| |_| |_____| |_) | (_| | || (__| | | |
 * |___/ .__/|_|  |_|_| |_|\__, |     |___/\___|\___|\__,_|_|  |_|\__|\__, |     | .__/ \__,_|\__\___|_| |_|
 *     |_|                 |___/                                      |___/      |_|
 *
 *  https://github.com/yingzhuo/spring-security-patch
 */
package com.github.yingzhuo.spring.security.jwt;

import com.github.yingzhuo.spring.security.jwt.parser.JwtTokenParser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

/**
 * @author 应卓
 */
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenParser tokenParser;
    private final AbstractJwtAuthenticationManager authManager;
    private final JwtAuthenticationFailedEntryPoint entryPoint;

    public JwtAuthenticationFilter(JwtTokenParser tokenParser, AbstractJwtAuthenticationManager authManager, JwtAuthenticationFailedEntryPoint entryPoint) {
        this.tokenParser = tokenParser;
        this.authManager = authManager;
        this.entryPoint = entryPoint;
    }

    @Override
    public void afterPropertiesSet() throws ServletException {
        super.afterPropertiesSet();
        Assert.notNull(tokenParser, () -> null);
        Assert.notNull(authManager, () -> null);
        Assert.notNull(entryPoint, () -> null);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        Optional<JwtToken> tokenOption = tokenParser.parse(request);

        try {
            if (tokenOption.isPresent()) {
                UsernamePasswordAuthenticationToken upt =
                        (UsernamePasswordAuthenticationToken) authManager.authenticate(tokenOption.orElse(null));

                upt.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(upt);
            }

        } catch (AuthenticationException failed) {

            SecurityContextHolder.clearContext();
            entryPoint.commence(request, response, failed);
            return;
        }

        filterChain.doFilter(request, response);
    }

}
