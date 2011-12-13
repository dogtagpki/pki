package netscape.security.util;

import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;

public class UniversalCharset extends Charset {

    public UniversalCharset() {
        super("ASN.1-Universal", null);
    }

    public boolean contains(Charset cs) {
        return false;
    }

    public CharsetDecoder newDecoder() {
        return new UniversalCharsetDecoder(this);
    }

    public CharsetEncoder newEncoder() {
        return new UniversalCharsetEncoder(this);
    }
}
