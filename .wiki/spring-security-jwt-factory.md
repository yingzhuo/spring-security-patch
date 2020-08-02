### 依赖

```xml
<dependency>
    <groupId>com.github.yingzhuo</groupId>
    <artifactId>spring-security-jwt-factory</artifactId>
    <version>[1.1.1,)</version>
</dependency>
```

### 登录`Controller`例子

```java
package com.github.yingzhuo.playground.controller;

import com.github.yingzhuo.spring.security.jwt.factory.JwtTokenFactory;
import com.github.yingzhuo.spring.security.jwt.factory.JwtTokenMetadata;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/security")
public class SecurityController {

    @Autowired
    private JwtTokenFactory tokenFactory;

    @GetMapping("/login")
    public String login() {
        return tokenFactory.create(JwtTokenMetadata
                .builder()
                .randomPrivateClaim()
                .issuer("应卓")
                .issuedAtNow()
                .expiresAtFuture(365L, TimeUnit.DAYS)
                .putPrivateClaim("username", "admin")
                .putPrivateClaim("roles", new String[] {"ROLE_ADMIN", "ROLE_USER"})
                .build()
        );
    }

}
```
