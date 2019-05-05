/*                 _                                            _ _                           _       _
 *  ___ _ __  _ __(_)_ __   __ _       ___  ___  ___ _   _ _ __(_) |_ _   _       _ __   __ _| |_ ___| |__
 * / __| '_ \| '__| | '_ \ / _` |_____/ __|/ _ \/ __| | | | '__| | __| | | |_____| '_ \ / _` | __/ __| '_ \
 * \__ \ |_) | |  | | | | | (_| |_____\__ \  __/ (__| |_| | |  | | |_| |_| |_____| |_) | (_| | || (__| | | |
 * |___/ .__/|_|  |_|_| |_|\__, |     |___/\___|\___|\__,_|_|  |_|\__|\__, |     | .__/ \__,_|\__\___|_| |_|
 *     |_|                 |___/                                      |___/      |_|
 *
 *  https://github.com/yingzhuo/spring-security-patch
 */
package com.github.yingzhuo.spring.security.jwt.errorhandler;

import com.github.yingzhuo.spring.security.jwt.exception.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * @author 应卓
 * @since 1.0.0
 */
public interface JwtErrorHandler extends AuthenticationEntryPoint {

    /**
     * Commences an authentication scheme.
     * <p>
     * <code>ExceptionTranslationFilter</code> will populate the <code>HttpSession</code>
     * attribute named
     * <code>AbstractAuthenticationProcessingFilter.SPRING_SECURITY_SAVED_REQUEST_KEY</code>
     * with the requested target URL before calling this method.
     * <p>
     * Implementations should modify the headers on the <code>ServletResponse</code> as
     * necessary to commence the authentication process.
     *
     * @param request       that resulted in an <code>AuthenticationException</code>
     * @param response      so that the user agent can begin authentication
     * @param authException that caused the invocation
     */
    @Override
    public default void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {

        if (authException instanceof AlgorithmMismatchException) {
            handleAlgorithmMismatchException(request, response, (AlgorithmMismatchException) authException);
            return;
        }

        if (authException instanceof InvalidClaimException) {
            handleInvalidClaimException(request, response, (InvalidClaimException) authException);
            return;
        }

        if (authException instanceof JwtDecodeException) {
            handleJwtDecodeException(request, response, (JwtDecodeException) authException);
            return;
        }

        if (authException instanceof SignatureVerificationException) {
            handleSignatureVerificationException(request, response, (SignatureVerificationException) authException);
            return;
        }

        if (authException instanceof TokenExpiredException) {
            handleTokenExpiredException(request, response, (TokenExpiredException) authException);
            return;
        }

        if (authException instanceof UnsupportedTokenException) {
            handleUnsupportedTokenException(request, response, (UnsupportedTokenException) authException);
            return;
        }

        if (authException instanceof UserDetailsNotFoundException) {
            handleUserDetailsNotFoundException(request, response, (UserDetailsNotFoundException) authException);
            return;
        }

        if (authException instanceof CredentialExpiredException) {
            handleCredentialExpiredException(request, response, (CredentialExpiredException) authException);
            return;
        }

        if (authException instanceof UserExpiredException) {
            handleUserExpiredException(request, response, (UserExpiredException) authException);
            return;
        }

        if (authException instanceof UserLockedException) {
            handleUserLockedException(request, response, (UserLockedException) authException);
            return;
        }

        handleDefault(request, response, authException);
    }

    public default void handleDefault(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.getOutputStream().write("403".getBytes(StandardCharsets.UTF_8));
    }

    public default void handleAlgorithmMismatchException(HttpServletRequest request, HttpServletResponse response, AlgorithmMismatchException authException) throws IOException {
        handleDefault(request, response, authException);
    }

    public default void handleInvalidClaimException(HttpServletRequest request, HttpServletResponse response, InvalidClaimException authException) throws IOException {
        handleDefault(request, response, authException);
    }

    public default void handleJwtDecodeException(HttpServletRequest request, HttpServletResponse response, JwtDecodeException authException) throws IOException {
        handleDefault(request, response, authException);
    }

    public default void handleSignatureVerificationException(HttpServletRequest request, HttpServletResponse response, SignatureVerificationException authException) throws IOException {
        handleDefault(request, response, authException);
    }

    public default void handleTokenExpiredException(HttpServletRequest request, HttpServletResponse response, TokenExpiredException authException) throws IOException {
        handleDefault(request, response, authException);
    }

    public default void handleUnsupportedTokenException(HttpServletRequest request, HttpServletResponse response, UnsupportedTokenException authException) throws IOException {
        handleDefault(request, response, authException);
    }

    public default void handleUserDetailsNotFoundException(HttpServletRequest request, HttpServletResponse response, UserDetailsNotFoundException authException) throws IOException {
        handleDefault(request, response, authException);
    }

    public default void handleCredentialExpiredException(HttpServletRequest request, HttpServletResponse response, CredentialExpiredException authException) throws IOException {
        handleDefault(request, response, authException);
    }

    public default void handleUserExpiredException(HttpServletRequest request, HttpServletResponse response, UserExpiredException authException) throws IOException {
        handleDefault(request, response, authException);
    }

    public default void handleUserLockedException(HttpServletRequest request, HttpServletResponse response, UserLockedException authException) throws IOException {
        handleDefault(request, response, authException);
    }

}
