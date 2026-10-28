package suspicious;

public class SuspiciousXorDecryptor {
    public void decryptAndExec() throws Exception {
        byte[] cipher = new byte[]{0x02, 0x0c, 0x05};
        byte key = 0x5a;
        for (int i = 0; i < cipher.length; i++) {
            cipher[i] = (byte)(cipher[i] ^ key);
        }
        Runtime.getRuntime().exec(new String(cipher));
    }
}