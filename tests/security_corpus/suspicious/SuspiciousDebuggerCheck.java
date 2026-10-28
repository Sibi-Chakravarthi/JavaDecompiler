package suspicious;

import java.lang.management.ManagementFactory;
import java.util.List;

public class SuspiciousDebuggerCheck {
    public boolean isDebuggerAttached() {
        List<String> args = ManagementFactory.getRuntimeMXBean().getInputArguments();
        for (String a : args) {
            if (a.contains("jdwp") || a.contains("debug")) {
                return true;
            }
        }
        return false;
    }
}