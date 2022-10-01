package top.gochiusa.smalljwt;

import org.json.JSONObject;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public final class JwtUtils {
    private JwtUtils() {}

    /**
     * 根据对应的签名算法，对数据进行HMAC签名
     * @param data 需要签名的数据
     * @param key 私钥
     * @param algorithm 签名算法
     * @return 签名后的字符串
     */
    static String signInternal(String data, String key, SignatureAlgorithm algorithm)
            throws NoSuchAlgorithmException, InvalidKeyException {
        Mac hmac = Mac.getInstance(algorithm.macName);
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), algorithm.macName);
        hmac.init(secretKey);
        byte[] array = hmac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(array);
    }

    /**
     * 确认token的签名是否有效
     * @param data 需要签名的数据
     * @param key 验证签名的
     * @param str 需要进行签名校验的字符串
     * @param algorithm 签名算法
     * @return 如果签名有效，返回true，否则返回false
     */
    static boolean confirmSignInternal(String data, String key, String str, SignatureAlgorithm algorithm)
            throws NoSuchAlgorithmException{
        try {
            return signInternal(data, key, algorithm).equals(str);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * JSON辅助方法，从JSON中取值或使用Default值
     * @param key 需要取出的键
     * @param <T> 默认值
     * @return 取出的值
     */
    static <T> T getOrDefault(JSONObject obj, String key, T defaultValue) {
        if (obj.has(key)) {
            return (T) obj.get(key);
        } else {
            return defaultValue;
        }
    }

    static long getLongOrDefault(JSONObject obj, String key, long defaultValue) {
        if (obj.has(key)) {
            return obj.getLong(key);
        } else {
            return defaultValue;
        }
    }
}
