package top.gochiusa.smalljwt;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static top.gochiusa.smalljwt.JwtConstant.*;
import static top.gochiusa.smalljwt.JwtConstant.POINT;

public final class JwtBuilder {
    String type;
    SignatureAlgorithm algorithm;
    String issuer;
    long expirationTime;
    long issuedAt;
    String subject;
    String audience;
    long jwtId;
    long notBefore;
    final Map<String, Object> map = new HashMap<>();

    public JwtBuilder() {
        this(SignatureAlgorithm.HS512);
    }

    public JwtBuilder(SignatureAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    public JwtBuilder setType(String type) {
        this.type = type;
        return this;
    }

    public JwtBuilder setAlgorithm(SignatureAlgorithm algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    public JwtBuilder setIssuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    public JwtBuilder setExpirationTime(long expirationTime) {
        this.expirationTime = expirationTime;
        return this;
    }

    public JwtBuilder setIssuedAt(long issuedAt) {
        this.issuedAt = issuedAt;
        return this;
    }

    public JwtBuilder setSubject(String subject) {
        this.subject = subject;
        return this;
    }

    public JwtBuilder setAudience(String audience) {
        this.audience = audience;
        return this;
    }

    public JwtBuilder setJwtId(long jwtId) {
        this.jwtId = jwtId;
        return this;
    }

    public JwtBuilder setNotBefore(long notBefore) {
        this.notBefore = notBefore;
        return this;
    }

    public JwtBuilder setMap(Map<String, Object> map) {
        this.map.putAll(map);
        return this;
    }

    public JwtBuilder append(String key, Object value) {
        map.put(key, value);
        return this;
    }

    public JwtBuilder clearMap() {
        map.clear();
        return this;
    }

    public JwtBuilder setJwt(Jwt jwt) {
        this.type = jwt.getType();
        this.algorithm = jwt.getAlgorithm();
        this.issuer = jwt.getIssuer();
        this.expirationTime = jwt.getExpirationTime();
        this.issuedAt = jwt.getIssuedAt();
        this.subject = jwt.getSubject();
        this.audience = jwt.getAudience();
        this.jwtId = jwt.getJwtId();
        this.notBefore = jwt.getNotBefore();
        return clearMap().setMap(jwt.getMap());
    }

    /**
     * 利用给定的签名私钥签署token
     * @param key 签名私钥
     * @return 合法的token，如果出错则返回空指针
     */
    public String signWith(String key) {
        JSONObject header = new JSONObject();
        if (type != null) {
            header.put(TYP, type);
        }
        header.put(ALG, algorithm.id);

        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String headerBase64 = encoder.encodeToString(
                header.toString().getBytes(StandardCharsets.UTF_8));

        JSONObject body = new JSONObject();
        if (issuer != null) {
            body.put(ISS, issuer);
        }
        if (expirationTime != 0L) {
            body.put(EXP, expirationTime);
        }
        if (issuedAt != 0L) {
            body.put(IAT, issuedAt);
        }
        if (subject != null) {
            body.put(SUB, subject);
        }
        if (audience != null) {
            body.put(AUD, audience);
        }
        if (jwtId != 0L) {
            body.put(JTI, jwtId);
        }
        if (notBefore != 0L) {
            body.put(NBF, notBefore);
        }
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            body.put(entry.getKey(), entry.getValue().toString());
        }
        String bodyBase64 = encoder.encodeToString(body.toString().getBytes(StandardCharsets.UTF_8));
        String data = headerBase64 + POINT + bodyBase64;
        try {
            String sign = JwtUtils.signInternal(data, key, algorithm);
            return data + POINT + sign;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    Jwt build() {
        return new Jwt(this);
    }
}
