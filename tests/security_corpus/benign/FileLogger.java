package benign;

import java.io.FileWriter;
import java.io.IOException;

public class FileLogger {
    public static void log(String path, String msg) throws IOException {
        try (FileWriter fw = new FileWriter(path, true)) {
            fw.write(msg + "\n");
        }
    }
}