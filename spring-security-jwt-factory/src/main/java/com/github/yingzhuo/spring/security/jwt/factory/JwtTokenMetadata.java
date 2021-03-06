/*                 _                                            _ _                           _       _
 *  ___ _ __  _ __(_)_ __   __ _       ___  ___  ___ _   _ _ __(_) |_ _   _       _ __   __ _| |_ ___| |__
 * / __| '_ \| '__| | '_ \ / _` |_____/ __|/ _ \/ __| | | | '__| | __| | | |_____| '_ \ / _` | __/ __| '_ \
 * \__ \ |_) | |  | | | | | (_| |_____\__ \  __/ (__| |_| | |  | | |_| |_| |_____| |_) | (_| | || (__| | | |
 * |___/ .__/|_|  |_|_| |_|\__, |     |___/\___|\___|\__,_|_|  |_|\__|\__, |     | .__/ \__,_|\__\___|_| |_|
 *     |_|                 |___/                                      |___/      |_|
 *
 *  https://github.com/yingzhuo/spring-security-patch
 */
package com.github.yingzhuo.spring.security.jwt.factory;

import java.io.Serializable;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * @author 应卓
 * @since 1.0.0
 */
public final class JwtTokenMetadata implements Serializable {

    // Public Claims (Header)
    private String keyId;
    private String issuer;
    private String subject;
    private List<String> audience = new ArrayList<>();
    private Date expiresAt;
    private Date notBefore;
    private Date issuedAt;
    private String jwtId;

    // Private Claims
    private Map<String, Object> privateClaims = new HashMap<>(0);

    private JwtTokenMetadata() {
    }

    public static Builder builder() {
        return new Builder();
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public List<String> getAudience() {
        return audience;
    }

    public void setAudience(List<String> audience) {
        this.audience = audience;
    }

    public Date getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Date expiresAt) {
        this.expiresAt = expiresAt;
    }

    public Date getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(Date notBefore) {
        this.notBefore = notBefore;
    }

    public Date getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(Date issuedAt) {
        this.issuedAt = issuedAt;
    }

    public String getJwtId() {
        return jwtId;
    }

    public void setJwtId(String jwtId) {
        this.jwtId = jwtId;
    }

    public Map<String, Object> getPrivateClaims() {
        return privateClaims;
    }

    public void setPrivateClaims(Map<String, Object> privateClaims) {
        this.privateClaims = privateClaims;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        JwtTokenMetadata that = (JwtTokenMetadata) o;
        return Objects.equals(keyId, that.keyId) &&
                Objects.equals(issuer, that.issuer) &&
                Objects.equals(subject, that.subject) &&
                Objects.equals(audience, that.audience) &&
                Objects.equals(expiresAt, that.expiresAt) &&
                Objects.equals(notBefore, that.notBefore) &&
                Objects.equals(issuedAt, that.issuedAt) &&
                Objects.equals(jwtId, that.jwtId) &&
                Objects.equals(privateClaims, that.privateClaims);
    }

    @Override
    public int hashCode() {
        return Objects.hash(keyId, issuer, subject, audience, expiresAt, notBefore, issuedAt, jwtId, privateClaims);
    }

    // -----------------------------------------------------------------------------------------------------------------

    public static class Builder {
        private String keyId;
        private String issuer;
        private String subject;
        private List<String> audience = new ArrayList<>();
        private Date expiresAt;
        private Date notBefore;
        private Date issuedAt;
        private String jwtId;
        private Map<String, Object> privateClaims = new HashMap<>();

        private Builder() {
        }

        public Builder keyId(String keyId) {
            this.keyId = keyId;
            return this;
        }

        public Builder keyId(Supplier<String> supplier) {
            return keyId(supplier.get());
        }

        public Builder issuer(String issuer) {
            this.issuer = issuer;
            return this;
        }

        public Builder subject(String subject) {
            this.subject = subject;
            return this;
        }

        public Builder audience(List<String> audience) {
            this.audience = audience;
            return this;
        }

        public Builder audience(String... audience) {
            return audience(Arrays.asList(audience));
        }

        public Builder expiresAt(Date expiresAt) {
            this.expiresAt = expiresAt;
            return this;
        }

        public Builder expiresAtFuture(long duration, TimeUnit timeUnit) {
            return expiresAt(afterNow(duration, timeUnit));
        }

        public Builder expiresAtFuture(Duration duration) {
            return expiresAtFuture(duration.toMillis(), TimeUnit.MILLISECONDS);
        }

        public Builder notBefore(Date notBefore) {
            this.notBefore = notBefore;
            return this;
        }

        public Builder notBeforeFuture(long duration, TimeUnit timeUnit) {
            return notBefore(this.afterNow(duration, timeUnit));
        }

        public Builder notBeforeFuture(Duration duration) {
            return notBeforeFuture(duration.toMillis(), TimeUnit.MILLISECONDS);
        }

        public Builder issuedAt(Date issuedAt) {
            this.issuedAt = issuedAt;
            return this;
        }

        public Builder issuedAtNow() {
            return issuedAt(new Date());
        }

        public Builder jwtId(String jwtId) {
            this.jwtId = jwtId;
            return this;
        }

        public Builder jwtId(Supplier<String> supplier) {
            return jwtId(supplier.get());
        }

        public Builder putPrivateClaim(String key, Boolean value) {
            return doPutPrivateClaim(key, value);
        }

        public Builder putPrivateClaim(String key, Date value) {
            return doPutPrivateClaim(key, value);
        }

        public Builder putPrivateClaim(String key, Double value) {
            return doPutPrivateClaim(key, value);
        }

        public Builder putPrivateClaim(String key, String value) {
            return doPutPrivateClaim(key, value);
        }

        public Builder putPrivateClaim(String key, String[] value) {
            return doPutPrivateClaim(key, value);
        }

        public Builder putPrivateClaim(String key, Integer value) {
            return doPutPrivateClaim(key, value);
        }

        public Builder putPrivateClaim(String key, Integer[] value) {
            return doPutPrivateClaim(key, value);
        }

        public Builder putPrivateClaim(String key, Long value) {
            return doPutPrivateClaim(key, value);
        }

        public Builder putPrivateClaim(String key, Long[] value) {
            return doPutPrivateClaim(key, value);
        }

        // since v1.0.2
        public Builder randomPrivateClaim() {
            return doPutPrivateClaim("_random_", randomString());
        }

        private Builder doPutPrivateClaim(String key, Object value) {
            Objects.requireNonNull(key);
            Objects.requireNonNull(value);
            this.privateClaims.put(key, value);
            return this;
        }

        public JwtTokenMetadata build() {
            JwtTokenMetadata meta = new JwtTokenMetadata();
            meta.jwtId = this.jwtId;
            meta.keyId = this.keyId;
            meta.issuer = this.issuer;
            meta.subject = this.subject;
            meta.audience = this.audience;
            meta.expiresAt = this.expiresAt;
            meta.notBefore = this.notBefore;
            meta.issuedAt = this.issuedAt;
            meta.privateClaims = this.privateClaims;
            return meta;
        }

        private Date afterNow(long duration, TimeUnit timeUnit) {
            Objects.requireNonNull(timeUnit);
            return new Date(System.currentTimeMillis() + timeUnit.toMillis(duration));
        }

        private String randomString() {
            return UUID.randomUUID().toString().replaceAll("-", "");
        }
    }

}
