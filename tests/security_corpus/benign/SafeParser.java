package benign;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

public class SafeParser {
    public static DocumentBuilderFactory createSecureFactory() throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        return dbf;
    }
}