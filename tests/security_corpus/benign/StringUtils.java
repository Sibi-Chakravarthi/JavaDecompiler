package benign;

public class StringUtils {
    public static String reverse(String input) {
        if (input == null) return null;
        return new StringBuilder(input).reverse().toString();
    }

    public static boolean isEmpty(String s) {
        return s == null || s.trim().isEmpty();
    }
}