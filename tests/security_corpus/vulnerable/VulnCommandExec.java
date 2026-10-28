package vulnerable;

import java.io.IOException;

public class VulnCommandExec {
    public void executeCommand(String userParam) throws IOException {
        Runtime.getRuntime().exec("sh -c " + userParam);
    }
}