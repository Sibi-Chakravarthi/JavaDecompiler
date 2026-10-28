package benign;

import java.io.Serializable;

public class SafeSerialization implements Serializable {
    private static final long serialVersionUID = 1L;
    private String label;

    public SafeSerialization(String label) {
        this.label = label;
    }

    public String getLabel() { return label; }
}