package vulnerable;

public class VulnHardcodedPem {
    public static final String PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0m4p...\n-----END RSA PRIVATE KEY-----";

    public String getPem() {
        return PRIVATE_KEY;
    }
}