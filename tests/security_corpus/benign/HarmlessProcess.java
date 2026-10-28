package benign;

import java.io.IOException;

public class HarmlessProcess {
    public static void runStatus() throws IOException {
        ProcessBuilder pb = new ProcessBuilder("echo", "healthy");
        pb.start();
    }
}