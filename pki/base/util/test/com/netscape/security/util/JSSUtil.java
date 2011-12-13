package com.netscape.security.util;

import netscape.security.util.DerValue;

import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.BMPString;
import org.mozilla.jss.asn1.IA5String;
import org.mozilla.jss.asn1.PrintableString;
import org.mozilla.jss.asn1.TeletexString;
import org.mozilla.jss.asn1.UTF8String;
import org.mozilla.jss.asn1.UniversalString;

public class JSSUtil {

    public static byte[] encode(byte tag, String string) throws Exception {
        ASN1Value value;

        switch (tag) {
            case DerValue.tag_BMPString:
                value = new BMPString(string);
                break;
            case DerValue.tag_IA5String:
                value = new IA5String(string);
                break;
            case DerValue.tag_PrintableString:
                value = new PrintableString(string);
                break;
            case DerValue.tag_T61String:
                value = new TeletexString(string);
                break;
            case DerValue.tag_UniversalString:
                value = new UniversalString(string);
                break;
            case DerValue.tag_UTF8String:
                value = new UTF8String(string);
                break;
            default:
                throw new Exception("Unsupported tag: "+tag);
        }
        return ASN1Util.encode(value);
    }
}
