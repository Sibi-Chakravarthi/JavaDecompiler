package suspicious;

import java.util.Base64;

public class SuspiciousDecodeExec {
    public void decodeAndRun() throws Exception {
        String encoded = "Y21kLmV4ZSAvYyBjYWxjLmV4ZQ==";
        byte[] decoded = Base64.getDecoder().decode(encoded);
        Runtime.getRuntime().exec(new String(decoded));
    }
}