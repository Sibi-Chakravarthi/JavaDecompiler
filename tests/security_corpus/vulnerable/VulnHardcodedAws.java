package vulnerable;

public class VulnHardcodedAws {
    public static final String AWS_SECRET = "AKIAIOSFODNN7EXAMPLE";

    public String getKey() {
        return AWS_SECRET;
    }
}