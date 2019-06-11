package com.netscape.security.x509;

import org.mozilla.jss.netscape.security.util.DerOutputStream;
import org.mozilla.jss.netscape.security.util.DerValue;
import org.mozilla.jss.netscape.security.x509.AVAValueConverter;

public class ConverterTestUtil {

    public static byte[] convert(AVAValueConverter converter, String string, byte[] tags) throws Exception {

        DerOutputStream os = new DerOutputStream();

        DerValue value = converter.getValue(string, tags);
        value.encode(os);

        return os.toByteArray();
    }

    public static byte[] convert(AVAValueConverter converter, String string) throws Exception {
        return convert(converter, string, null);
    }
}
