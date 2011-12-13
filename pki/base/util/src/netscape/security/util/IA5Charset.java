package netscape.security.util;

import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;

public class IA5Charset extends Charset {

    public IA5Charset() {
        super("ASN.1-IA5", null);
    }

    public boolean contains(Charset cs) {
        return false;
    }

    public CharsetDecoder newDecoder() {
        return new IA5CharsetDecoder(this);
    }

    public CharsetEncoder newEncoder() {
        return new IA5CharsetEncoder(this);
    }
}
