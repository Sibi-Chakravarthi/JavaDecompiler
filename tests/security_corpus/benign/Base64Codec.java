package benign;

import java.util.Base64;

public class Base64Codec {
    public static String encodeText(String msg) {
        return Base64.getEncoder().encodeToString(msg.getBytes());
    }

    public static String decodeText(String b64) {
        return new String(Base64.getDecoder().decode(b64));
    }
}