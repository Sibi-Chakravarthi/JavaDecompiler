package suspicious;

public class SuspiciousNativeLoad {
    public void loadEvilLibrary() {
        System.loadLibrary("evil_native_payload");
    }
}