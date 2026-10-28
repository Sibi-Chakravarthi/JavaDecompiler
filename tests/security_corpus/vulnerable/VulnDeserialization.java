package vulnerable;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;

public class VulnDeserialization {
    public Object deserializePayload(byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();
    }
}