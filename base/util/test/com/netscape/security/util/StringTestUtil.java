package com.netscape.security.util;

import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

public class StringTestUtil {

    public final static String NULL_CHARS = "\u0000";

    public final static String PRINTABLE_CHARS =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 \'()+,-./:=?";

    public final static String NON_PRINTABLE_CHARS = "\"\\";

    public final static String CONTROL_CHARS = "\b\t\n\f\r";

    public final static String MULTIBYTE_CHARS = "我爱你"; // I love you

    public static String toString(byte[] array) {

        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < array.length; i++) {
            if (i > 0)
                sb.append(" ");
            sb.append(Integer.toHexString(0xff & array[i] | 0x100).substring(1).toUpperCase());
        }

        return sb.toString();
    }

    public static byte[] normalizeUnicode(byte[] data) throws Exception {

        try (DerOutputStream os = new DerOutputStream()) {
            DerValue value = new DerValue(data);
            byte[] tmp = value.data.toByteArray();

            if (tmp[0] == -2 && tmp[1] == -1) { // remove optional big-endian byte-order mark

                byte tag = value.tag;
                int length = value.length() - 2;

                os.putTag((byte) 0, false, tag);
                os.putLength(length);
                os.write(tmp, 2, length);

                return os.toByteArray();
            }

            return data;
        }
    }

    public static byte[] encode(byte tag, String string) throws Exception {
        try (DerOutputStream os = new DerOutputStream()) {
            os.putStringType(tag, string);
            return os.toByteArray();
        }
    }

    public static String decode(byte tag, byte[] bytes) throws Exception {
        DerInputStream is = new DerInputStream(bytes);

        switch (tag) {
        case DerValue.tag_BMPString:
            return is.getBMPString();
        case DerValue.tag_IA5String:
            return is.getIA5String();
        case DerValue.tag_PrintableString:
            return is.getPrintableString();
        case DerValue.tag_T61String:
            return is.getT61String();
        case DerValue.tag_UniversalString:
            return is.getUniversalString();
        case DerValue.tag_UTF8String:
            return is.getDerValue().getUTF8String();
        default:
            throw new Exception("Unsupported tag: " + tag);
        }
    }
}
