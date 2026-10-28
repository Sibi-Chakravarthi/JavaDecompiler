package vulnerable;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

public class VulnPermissiveHost implements HostnameVerifier {
    public boolean verify(String hostname, SSLSession session) {
        return true;
    }
}