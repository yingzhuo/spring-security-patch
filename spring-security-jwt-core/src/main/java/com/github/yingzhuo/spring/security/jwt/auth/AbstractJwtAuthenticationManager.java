/*                 _                                            _ _                           _       _
 *  ___ _ __  _ __(_)_ __   __ _       ___  ___  ___ _   _ _ __(_) |_ _   _       _ __   __ _| |_ ___| |__
 * / __| '_ \| '__| | '_ \ / _` |_____/ __|/ _ \/ __| | | | '__| | __| | | |_____| '_ \ / _` | __/ __| '_ \
 * \__ \ |_) | |  | | | | | (_| |_____\__ \  __/ (__| |_| | |  | | |_| |_| |_____| |_) | (_| | || (__| | | |
 * |___/ .__/|_|  |_|_| |_|\__, |     |___/\___|\___|\__,_|_|  |_|\__|\__, |     | .__/ \__,_|\__\___|_| |_|
 *     |_|                 |___/                                      |___/      |_|
 *
 *  https://github.com/yingzhuo/spring-security-patch
 */
package com.github.yingzhuo.spring.security.jwt.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.github.yingzhuo.spring.security.jwt.JwtToken;
import com.github.yingzhuo.spring.security.jwt.algorithm.AlgorithmFactories;
import com.github.yingzhuo.spring.security.jwt.algorithm.AlgorithmFactory;
import com.github.yingzhuo.spring.security.jwt.exception.*;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.HashSet;

/**
 * @author 应卓
 * @since 1.0.0
 */
public abstract class AbstractJwtAuthenticationManager implements AuthenticationManager, InitializingBean {

    private final Algorithm algorithm;

    public AbstractJwtAuthenticationManager() {
        this(AlgorithmFactories.getDefault());
    }

    public AbstractJwtAuthenticationManager(AlgorithmFactory algorithmFactory) {
        this.algorithm = algorithmFactory.create();
    }

    @Override
    public final Authentication authenticate(Authentication token) throws AuthenticationException {

        if (!(token instanceof JwtToken)) {
            throw new UnsupportedTokenException();
        }

        try {
            final JWTVerifier verifier = JWT.require(algorithm).build();

            String rawToken = ((JwtToken) token).getRawToken();
            DecodedJWT jwt = verifier.verify(rawToken);

            final UserDetails userDetails = doAuthenticate(rawToken, jwt);

            if (userDetails == null) {
                throw new UserDetailsNotFoundException();
            }

            if (!userDetails.isAccountNonExpired()) {
                throw new UserExpiredException();
            }

            if (!userDetails.isAccountNonLocked()) {
                throw new UserLockedException();
            }

            if (!userDetails.isCredentialsNonExpired()) {
                throw new CredentialExpiredException();
            }

            UsernamePasswordAuthenticationToken upt = new UsernamePasswordAuthenticationToken(
                    userDetails,
                    rawToken,
                    userDetails.getAuthorities() != null ? userDetails.getAuthorities() : new HashSet<>());

            SecurityContextHolder.getContext().setAuthentication(upt);

            return upt;

        } catch (com.auth0.jwt.exceptions.AlgorithmMismatchException ex) {
            throw new AlgorithmMismatchException(ex.getMessage(), ex);
        } catch (com.auth0.jwt.exceptions.TokenExpiredException ex) {
            throw new TokenExpiredException(ex.getMessage(), ex);
        } catch (com.auth0.jwt.exceptions.SignatureVerificationException ex) {
            throw new SignatureVerificationException(ex.getMessage(), ex);
        } catch (com.auth0.jwt.exceptions.InvalidClaimException ex) {
            throw new InvalidClaimException(ex.getMessage(), ex);
        } catch (com.auth0.jwt.exceptions.JWTDecodeException ex) {
            throw new JwtDecodeException(ex.getMessage(), ex);
        }
    }

    protected abstract UserDetails doAuthenticate(String rawToken, DecodedJWT jwt) throws AuthenticationException;

    @Override
    public void afterPropertiesSet() {
        // nop
    }

}
