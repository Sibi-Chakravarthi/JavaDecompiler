package suspicious;

public class SuspiciousTimeBomb {
    public void checkTimeAndExecute() throws Exception {
        long target = 1893456000000L;
        if (System.currentTimeMillis() > target) {
            Runtime.getRuntime().exec("notepad.exe");
        }
    }
}