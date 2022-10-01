package top.gochiusa.smalljwt;

public enum SignatureAlgorithm {

    HS224("HS224", "HmacSHA224"),
    HS256("HS256", "HmacSHA256"),
    HS384("HS384", "HmacSHA384"),
    HS512("HS512", "HmacSHA512");

    public final String id;

    public final String macName;

    SignatureAlgorithm(String id, String macName) {
        this.id = id;
        this.macName = macName;
    }
}
