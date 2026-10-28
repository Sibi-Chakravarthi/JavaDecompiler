package vulnerable;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class VulnWeakCipher {
    public byte[] encryptData(SecretKey key, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("DES");
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(data);
    }
}