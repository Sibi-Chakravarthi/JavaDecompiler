package vulnerable;

import java.io.File;
import java.io.FileOutputStream;

public class VulnPathTraversal {
    public void extractFile(File destDir, String entryName, byte[] data) throws Exception {
        File target = new File(destDir, entryName);
        FileOutputStream fos = new FileOutputStream(target);
        fos.write(data);
        fos.close();
    }
}