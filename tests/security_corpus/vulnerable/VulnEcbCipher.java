package vulnerable;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class VulnEcbCipher {
    public byte[] encryptEcb(SecretKey key, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(data);
    }
}