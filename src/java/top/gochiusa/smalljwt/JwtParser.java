package top.gochiusa.smalljwt;

import org.json.JSONObject;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;

import static top.gochiusa.smalljwt.JwtConstant.*;

public final class JwtParser {
    private String verifyKey;
    private JSONParser extraParser;

    public JwtParser() {
        extraParser = JSONObject::toMap;
    }

    public JwtParser setVerifySignKey(String verifyKey) {
        this.verifyKey = verifyKey;
        return this;
    }

    public JwtParser setExtraJSONParser(JSONParser extraParser) {
        this.extraParser = extraParser;
        return this;
    }

    public Jwt parseJwt(String token) throws JwtException {
        int firstIndex = token.indexOf(POINT);
        int lastIndex = token.lastIndexOf(POINT);
        if (firstIndex == lastIndex || firstIndex == -1 || lastIndex == -1) {
            throw new JwtException("Token不合法");
        }
        Base64.Decoder decoder = Base64.getUrlDecoder();
        JSONObject header = new JSONObject(new String(decoder.decode(token.substring(0, firstIndex))));
        SignatureAlgorithm algorithm;
        try {
            algorithm = SignatureAlgorithm.valueOf(header.getString(ALG));
        } catch (IllegalArgumentException e) {
            throw new JwtException("未知的签名算法");
        }
        try {
            boolean result = JwtUtils.confirmSignInternal(token.substring(0, lastIndex), verifyKey,
                    token.substring(lastIndex + 1), algorithm);
            if (!result) {
                throw new JwtException("Token无法通过校验");
            }
        } catch (NoSuchAlgorithmException e) {
            throw new JwtException("本机无法支持的签名算法");
        }

        JSONObject body = new JSONObject(new String(decoder.decode(token.substring(firstIndex + 1, lastIndex))));
        JwtBuilder builder = new JwtBuilder();
        try {
            builder.setType(JwtUtils.getOrDefault(header, TYP, null))
                    .setAlgorithm(algorithm)
                    .setIssuer(JwtUtils.getOrDefault(body, ISS, null))
                    .setSubject(JwtUtils.getOrDefault(body, SUB, null))
                    .setIssuedAt(JwtUtils.getLongOrDefault(body, IAT, 0L))
                    .setJwtId(JwtUtils.getLongOrDefault(body, JTI, 0L))
                    .setAudience(JwtUtils.getOrDefault(body, AUD, null))
                    .setExpirationTime(JwtUtils.getLongOrDefault(body, EXP, 0L))
                    .setNotBefore(JwtUtils.getLongOrDefault(body, NBF, 0L));
            if (extraParser != null) {
                builder.setMap(extraParser.parse(body));
            }
            return builder.build();
        } catch (Exception e) {
            e.printStackTrace();
            throw new JwtException("解析Token携带的信息时出错");
        }
    }

    /**
     * 处理自定义JSON数据的适配类
     */
    public interface JSONParser {
        Map<String, Object> parse(JSONObject object);
    }
}
