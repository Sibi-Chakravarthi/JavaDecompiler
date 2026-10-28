import java.io.File;
import java.io.FileOutputStream;
import java.net.Socket;
import java.security.MessageDigest;

public class NetworkCryptoService {
    public static void sendHash(String host, int port, byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(data);
        Socket sock = new Socket(host, port);
        sock.getOutputStream().write(hash);
        sock.close();
    }

    public static void saveToFile(String filePath, byte[] content) throws Exception {
        File file = new File(filePath);
        FileOutputStream fos = new FileOutputStream(file);
        fos.write(content);
        fos.close();
    }
}
