package suspicious;

public class SuspiciousShutdownHook {
    public void installPersistence() {
        Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
            public void run() {
                try {
                    Runtime.getRuntime().exec("calc.exe");
                } catch (Exception ignored) {}
            }
        }));
    }
}