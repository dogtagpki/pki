package netscape.security.util;

import java.nio.charset.Charset;
import java.nio.charset.spi.CharsetProvider;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class ASN1CharsetProvider extends CharsetProvider {

    protected Map<String, Charset> charsets = new HashMap<String, Charset>();

    public ASN1CharsetProvider() {
        addCharset(new PrintableCharset());
        addCharset(new IA5Charset());
        addCharset(new UniversalCharset());
    }

    public Iterator<Charset> charsets() {
        return charsets.values().iterator();
    }

    public Charset charsetForName(String charsetName) {
        return charsets.get(charsetName);
    }

    public void addCharset(Charset cs) {
        charsets.put(cs.name(), cs);
    }
}
