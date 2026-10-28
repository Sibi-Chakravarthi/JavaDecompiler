package vulnerable;

import java.util.Random;

public class VulnInsecureRandom {
    public int generateToken() {
        Random r = new Random();
        return r.nextInt();
    }
}