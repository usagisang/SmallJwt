# SmallJwt
一个小型的 Jwt (JSON Web Token) 库，可以用来进行 Token 的签发和验证
## 签发 Token
使用示例:
```java
final String key = "d5553d5ac6a854be853af288df8deb42";
long now = System.currentTimeMillis();
JwtBuilder builder = new JwtBuilder();
// 设置Token包含的信息
builder.setAlgorithm(SignatureAlgorithm.HS256)         // 签名算法
        .setType("JWT")
        .setIssuer("usagisang")                        // 签发实体
        .setIssuedAt(now)                              // 签发时间
        .setNotBefore(now)                             // 从签发的时候开始生效
        .setExpirationTime(now + 1000 * 60 * 60 * 24)  // 一小时后过期
        .setAudience("example.com")                    // Token被允许用来访问哪个主题
        .setJwtId(100)                                 
        .setSubject("user data")                       // 主题
        .append("uid", 123456);                        // 自定义数据
// 签发Token
String token = builder.signWith(key);
```

## 解析 / 验证 Token
使用示例:
```java
final String key = "d5553d5ac6a854be853af288df8deb42";
String token = "......";
JwtParser parser = new JwtParser();
try {
    // 解析的结果保存在数据类中
    Jwt jwt = parser.setVerifySignKey(key).parseJwt(token);
    System.out.println(jwt);
} catch (JwtException e) {
    // 如果token非法或者使用了不支持的签名算法或者Token无法通过签名验证，都会抛出异常
    e.printStackTrace();
}
```

## 支持的算法
**对称加密**
- HmacSHA算法，包括HS224、HS256、HS384、HS512

## 依赖的库

- [JSON in Java](https://github.com/stleary/JSON-java)