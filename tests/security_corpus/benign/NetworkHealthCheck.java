package benign;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

public class NetworkHealthCheck {
    public static int pingEndpoint(String targetUrl) throws IOException {
        URL url = new URL(targetUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(3000);
        return conn.getResponseCode();
    }
}