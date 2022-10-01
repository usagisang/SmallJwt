package top.gochiusa.smalljwt;

public class JwtException extends Exception {
    public JwtException() {
        super();
    }

    public JwtException(String msg) {
        super(msg);
    }

    public JwtException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public JwtException(Throwable cause) {
        super(cause);
    }
}
