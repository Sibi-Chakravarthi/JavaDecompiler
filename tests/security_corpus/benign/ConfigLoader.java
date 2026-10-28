package benign;

import java.io.InputStream;
import java.io.IOException;
import java.util.Properties;

public class ConfigLoader {
    public static Properties loadConfig(InputStream in) throws IOException {
        Properties props = new Properties();
        props.load(in);
        return props;
    }
}