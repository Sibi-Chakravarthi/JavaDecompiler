package benign;

import java.io.File;
import java.io.IOException;

public class SafePathReader {
    public static File getSafeFile(File baseDir, String userPath) throws IOException {
        File target = new File(baseDir, userPath);
        String canonicalBase = baseDir.getCanonicalPath();
        String canonicalTarget = target.getCanonicalPath();
        if (!canonicalTarget.startsWith(canonicalBase + File.separator)) {
            throw new SecurityException("Path traversal attempt detected!");
        }
        return target;
    }
}