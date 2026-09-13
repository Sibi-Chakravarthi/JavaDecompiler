public class CombinedTest {
    public static int sumEvens(int limit) {
        int sum = 0;
        int i = 0;
        while (i < limit) {
            if (i % 2 == 0) {
                sum = sum + i;
            } else {
                sum = sum - 1;
            }
            i = i + 1;
        }
        return sum;
    }

    public static void main(String[] args) {
        sumEvens(10);
    }
}
