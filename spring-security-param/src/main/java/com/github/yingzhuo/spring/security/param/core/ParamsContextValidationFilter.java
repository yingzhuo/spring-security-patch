/*                 _                                            _ _                           _       _
 *  ___ _ __  _ __(_)_ __   __ _       ___  ___  ___ _   _ _ __(_) |_ _   _       _ __   __ _| |_ ___| |__
 * / __| '_ \| '__| | '_ \ / _` |_____/ __|/ _ \/ __| | | | '__| | __| | | |_____| '_ \ / _` | __/ __| '_ \
 * \__ \ |_) | |  | | | | | (_| |_____\__ \  __/ (__| |_| | |  | | |_| |_| |_____| |_) | (_| | || (__| | | |
 * |___/ .__/|_|  |_|_| |_|\__, |     |___/\___|\___|\__,_|_|  |_|\__|\__, |     | .__/ \__,_|\__\___|_| |_|
 *     |_|                 |___/                                      |___/      |_|
 *
 *  https://github.com/yingzhuo/spring-security-patch
 */
package com.github.yingzhuo.spring.security.param.core;

import com.github.yingzhuo.spring.security.common.DebugMode;
import com.github.yingzhuo.spring.security.common.Debugger;
import com.github.yingzhuo.spring.security.param.ParamsContext;
import com.github.yingzhuo.spring.security.param.exception.ParamsValidationException;
import com.github.yingzhuo.spring.security.param.resolver.ParamsContextResolver;
import com.github.yingzhuo.spring.security.param.validation.ParamsValidationAlgorithm;
import org.slf4j.LoggerFactory;
import org.springframework.util.Assert;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;

/**
 * @author 应卓
 * @since 1.1.3
 */
public class ParamsContextValidationFilter extends OncePerRequestFilter {

    private ParamsContextResolver paramsContextResolver;
    private ParamsValidationAlgorithm paramsValidationAlgorithm;
    private Duration maxDiff;
    private DebugMode debugMode;
    private Debugger debugger;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String path = request.getRequestURI();
        final String method = request.getMethod().toUpperCase();
        final ParamsContext paramsContext = paramsContextResolver.resolve(new ServletWebRequest(request, response));

        if (paramsContext == null) {
            debugger.debug("[{}][{}] 无法解析出ParamsContext", path, method);
            throw new ParamsValidationException();
        }

        if (paramsContext.getNonce() == null) {
            debugger.debug("[{}][{}] 无法解析出ParamsContext的项 nonce", path, method);
            throw new ParamsValidationException();
        }

        if (paramsContext.getSign() == null) {
            debugger.debug("[{}][{}] 无法解析出ParamsContext的项 sign", path, method);
            throw new ParamsValidationException();
        }

        if (maxDiff != null) {
            Long timestamp = paramsContext.getTimestamp();
            if (timestamp == null) {
                debugger.debug("[{}][{}] 无法解析出ParamsContext的项 timestamp", path, method);
                throw new ParamsValidationException();
            }

            long diff = Math.abs(System.currentTimeMillis() - timestamp);
            if (diff > Math.abs(maxDiff.toMillis())) {
                debugger.debug("[{}][{}] timestamp已过期", path, method);
                throw new ParamsValidationException();
            }
        }

        final String mergedParams = paramsValidationAlgorithm.merge(request.getParameterMap(), paramsContextResolver.getSignParamName());
        debugger.debug("[{}][{}] mergedParams = {}", path, method, mergedParams);
        final String hashedParams = paramsValidationAlgorithm.encode(mergedParams);
        debugger.debug("[{}][{}] hashedParams = {}", path, method, hashedParams);

        if (!paramsValidationAlgorithm.matches(hashedParams, paramsContext.getSign())) {
            debugger.debug("[{}][{}] sign = {}", path, method, paramsContext.getSign());
            debugger.debug("[{}][{}] sign不正确", path, method);
            throw new ParamsValidationException();
        }

        filterChain.doFilter(request, response);
    }

    @Override
    public void afterPropertiesSet() throws ServletException {
        super.afterPropertiesSet();
        Assert.notNull(paramsContextResolver, () -> null);
        Assert.notNull(paramsValidationAlgorithm, () -> null);
        this.debugger = Debugger.of(LoggerFactory.getLogger(ParamsContextValidationFilter.class), debugMode);
    }

    public void setParamsContextResolver(ParamsContextResolver paramsContextResolver) {
        this.paramsContextResolver = paramsContextResolver;
    }

    public void setDebugMode(DebugMode debugMode) {
        this.debugMode = debugMode;
    }

    public void setParamsValidationAlgorithm(ParamsValidationAlgorithm paramsValidationAlgorithm) {
        this.paramsValidationAlgorithm = paramsValidationAlgorithm;
    }

    public void setMaxDiff(Duration maxDiff) {
        this.maxDiff = maxDiff;
    }

}
