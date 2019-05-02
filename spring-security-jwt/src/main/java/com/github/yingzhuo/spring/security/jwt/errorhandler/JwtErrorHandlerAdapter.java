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
import org.apache.commons.io.IOUtils;
import org.springframework.security.core.AuthenticationException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * @author 应卓
 */
public class JwtErrorHandlerAdapter implements JwtErrorHandler {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {

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

    protected void handleDefault(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        IOUtils.write("403", response.getOutputStream(), StandardCharsets.UTF_8);
    }

    protected void handleAlgorithmMismatchException(HttpServletRequest request, HttpServletResponse response, AlgorithmMismatchException authException) throws IOException {
        handleDefault(request, response, authException);
    }

    protected void handleInvalidClaimException(HttpServletRequest request, HttpServletResponse response, InvalidClaimException authException) throws IOException {
        handleDefault(request, response, authException);
    }

    protected void handleJwtDecodeException(HttpServletRequest request, HttpServletResponse response, JwtDecodeException authException) throws IOException {
        handleDefault(request, response, authException);
    }

    protected void handleSignatureVerificationException(HttpServletRequest request, HttpServletResponse response, SignatureVerificationException authException) throws IOException {
        handleDefault(request, response, authException);
    }

    protected void handleTokenExpiredException(HttpServletRequest request, HttpServletResponse response, TokenExpiredException authException) throws IOException {
        handleDefault(request, response, authException);
    }

    protected void handleUnsupportedTokenException(HttpServletRequest request, HttpServletResponse response, UnsupportedTokenException authException) throws IOException {
        handleDefault(request, response, authException);
    }

    protected void handleUserDetailsNotFoundException(HttpServletRequest request, HttpServletResponse response, UserDetailsNotFoundException authException) throws IOException {
        handleDefault(request, response, authException);
    }

    protected void handleCredentialExpiredException(HttpServletRequest request, HttpServletResponse response, CredentialExpiredException authException) throws IOException {
        handleDefault(request, response, authException);
    }

    protected void handleUserExpiredException(HttpServletRequest request, HttpServletResponse response, UserExpiredException authException) throws IOException {
        handleDefault(request, response, authException);
    }

    protected void handleUserLockedException(HttpServletRequest request, HttpServletResponse response, UserLockedException authException) throws IOException {
        handleDefault(request, response, authException);
    }

}
