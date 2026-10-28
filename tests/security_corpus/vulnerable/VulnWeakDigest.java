package vulnerable;

import java.security.MessageDigest;

public class VulnWeakDigest {
    public byte[] hashPassword(byte[] pass) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(pass);
    }
}