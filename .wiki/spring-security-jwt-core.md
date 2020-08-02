### 依赖这个项目

```xml
<dependency>
    <groupId>com.github.yingzhuo</groupId>
    <artifactId>spring-security-jwt-core</artifactId>
    <version>[1.1.1,)</version>
</dependency>
```

### 使用`spring-security`框架

```java
package com.github.yingzhuo.playground;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.github.yingzhuo.spring.security.jwt.AbstractJwtAuthenticationManager;
import com.github.yingzhuo.spring.security.jwt.errorhandler.JwtAuthenticationEntryPoint;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@EnableWebSecurity
public class ApplicationCnfSecurity extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.httpBasic()
                .disable();

        http.csrf()
                .disable();

        http.cors()
                .disable();

        http.logout()
                .disable();

        http.formLogin()
                .disable();

        http.authorizeRequests()
                .antMatchers("/ping").hasAnyRole("ADMIN", "USER")
                .antMatchers("/security/login").permitAll()
                .antMatchers("/actuator/**").permitAll()
                .anyRequest().permitAll();

        http.exceptionHandling().authenticationEntryPoint(new DefaultJwtAuthenticationEntryPoint());
    }

    @Component
    public static class JwtAuthManager extends AbstractJwtAuthenticationManager {

        @Override
        protected UserDetails doAuthenticate(String rawToken, DecodedJWT jwt) throws AuthenticationException {
            return User.builder()
                    .username(jwt.getClaim("username").asString())
                    .password("****")
                    .authorities(jwt.getClaim("roles").asArray(String.class))
                    .build();
        }
    }

    @Component
    public static class DefaultJwtAuthenticationEntryPoint extends JwtAuthenticationEntryPoint {
    }

}
```
