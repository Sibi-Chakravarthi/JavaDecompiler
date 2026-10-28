package benign;

import java.util.ArrayList;
import java.util.List;

public class CollectionHelper {
    public static List<Integer> filterEvens(List<Integer> list) {
        List<Integer> out = new ArrayList<>();
        for (Integer n : list) {
            if (n % 2 == 0) out.add(n);
        }
        return out;
    }
}