package benign;

import java.util.HashMap;
import java.util.Map;

public class BenignClinit {
    private static final Map<String, Integer> LOOKUP = new HashMap<>();

    static {
        LOOKUP.put("alpha", 1);
        LOOKUP.put("beta", 2);
        LOOKUP.put("gamma", 3);
    }

    public static int getVal(String key) {
        return LOOKUP.getOrDefault(key, 0);
    }
}