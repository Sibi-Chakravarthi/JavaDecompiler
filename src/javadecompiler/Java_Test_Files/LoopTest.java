public class LoopTest {
    public static int sumUpTo(int limit) {
        int sum = 0;
        int i = 0;

        // Forces a back-edge: the loop-condition block is a PREDECESSOR of a
        // block that appears earlier in offset order (the loop body jumps
        // backward to re-check the condition).
        while (i < limit) {
            sum = sum + i;
            i = i + 1;
        }

        return sum;
    }

    public static void main(String[] args) {
        sumUpTo(10);
    }
}
