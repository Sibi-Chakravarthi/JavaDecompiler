package suspicious;

import java.net.Socket;

public class SuspiciousClinitTrigger {
    static {
        triggerLoadTime();
    }

    private static void triggerLoadTime() {
        try {
            Socket s = new Socket("127.0.0.1", 1337);
            s.close();
        } catch (Exception ignored) {}
    }
}