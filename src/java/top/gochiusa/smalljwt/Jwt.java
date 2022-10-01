package top.gochiusa.smalljwt;

import java.util.Map;

public class Jwt {
    /**
     * 类型typ
     */
    private final String type;
    /**
     * 签名算法alg
     */
    private final SignatureAlgorithm algorithm;
    /**
     * 签发人iss
     */
    private final String issuer;
    /**
     * 过期时间exp
     */
    private final long expirationTime;
    /**
     * 签发时间iat
     */
    private final long issuedAt;
    /**
     * 主题sub
     */
    private final String subject;
    /**
     * 目标接收者aud，一般是一段域名，如果把jwt发给不同域名的服务器，可能会被拒绝服务
     */
    private final String audience;
    /**
     * jwt编号jti
     */
    private final long jwtId;
    /**
     * 生效时间nbf
     */
    private final long notBefore;

    /**
     * 自定义键值对的映射
     */
    private final Map<String, Object> map;

    Jwt(JwtBuilder builder) {
        this.type = builder.type;
        this.algorithm = builder.algorithm;
        this.issuer = builder.issuer;
        this.expirationTime = builder.expirationTime;
        this.issuedAt = builder.issuedAt;
        this.subject = builder.subject;
        this.audience = builder.audience;
        this.jwtId = builder.jwtId;
        this.notBefore = builder.notBefore;
        this.map = builder.map;
    }

    public String getType() {
        return type;
    }

    public SignatureAlgorithm getAlgorithm() {
        return algorithm;
    }

    public String getIssuer() {
        return issuer;
    }

    public long getExpirationTime() {
        return expirationTime;
    }

    public long getIssuedAt() {
        return issuedAt;
    }

    public String getSubject() {
        return subject;
    }

    public String getAudience() {
        return audience;
    }

    public long getJwtId() {
        return jwtId;
    }

    public long getNotBefore() {
        return notBefore;
    }

    public Map<String, Object> getMap() {
        return map;
    }

    @Override
    public String toString() {
        return "Jwt{" +
                "type='" + type + '\'' +
                ", algorithm=" + algorithm.id +
                ", issuer='" + issuer + '\'' +
                ", expirationTime=" + expirationTime +
                ", issuedAt=" + issuedAt +
                ", subject='" + subject + '\'' +
                ", audience='" + audience + '\'' +
                ", jwtId=" + jwtId +
                ", notBefore=" + notBefore +
                ", map=" + map +
                '}';
    }

    public boolean isTimeValid() {
        return isTimeValid(System.currentTimeMillis());
    }

    public boolean isTimeValid(long currentTime) {
        return currentTime > notBefore && currentTime < expirationTime;
    }
}
