package benign;

public class MathUtils {
    public static int add(int a, int b) {
        return a + b;
    }

    public static boolean isPrime(int n) {
        if (n <= 1) return false;
        for (int i = 2; i * i <= n; i++) {
            if (n % i == 0) return false;
        }
        return true;
    }
}