package netscape.security.util;

import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;

public class PrintableCharset extends Charset {

    public PrintableCharset() {
        super("ASN.1-Printable", null);
    }

    public static boolean isPrintableChar(char c) {
        if ((c < 'A' || c > 'Z') &&
                (c < 'a' || c > 'z') &&
                (c < '0' || c > '9') &&
                (c != ' ') &&
                (c != '\'') &&
                (c != '(') &&
                (c != ')') &&
                (c != '+') &&
                (c != ',') &&
                (c != '-') &&
                (c != '.') &&
                (c != '/') &&
                (c != ':') &&
                (c != '=') &&
                (c != '?')) {
            return false;
        } else {
            return true;
        }
    }

    public boolean contains(Charset cs) {
        return false;
    }

    public CharsetDecoder newDecoder() {
        return new PrintableCharsetDecoder(this);
    }

    public CharsetEncoder newEncoder() {
        return new PrintableCharsetEncoder(this);
    }
}
