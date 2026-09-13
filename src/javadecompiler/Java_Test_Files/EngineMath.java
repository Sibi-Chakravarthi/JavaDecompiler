public class EngineMath {
    public static int calculateHealth(int baseHealth, int damage) {
        int currentHealth = baseHealth - damage; // Forces 'iload' and 'isub'
        
        // This conditional forces an 'ifeq' and a 'goto' jump instruction
        if (currentHealth == 0) {
            currentHealth = 100; // Forces 'bipush' (push byte 100)
        } else {
            currentHealth = currentHealth + 5; // Forces 'iconst_5' or 'bipush' and 'iadd'
        }
        
        return currentHealth; // Forces 'ireturn'
    }

    public static void main(String[] args) {
        calculateHealth(20, 20);
    }
}