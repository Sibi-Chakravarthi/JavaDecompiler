package vulnerable;

public class VulnReflection {
    public Object createInstance(String className) throws Exception {
        return Class.forName(className).newInstance();
    }
}