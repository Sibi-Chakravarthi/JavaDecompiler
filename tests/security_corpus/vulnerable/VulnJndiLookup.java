package vulnerable;

import javax.naming.InitialContext;

public class VulnJndiLookup {
    public Object fetchRemote(String url) throws Exception {
        InitialContext ctx = new InitialContext();
        return ctx.lookup(url);
    }
}