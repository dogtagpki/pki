package com.netscape.certsrv.cert;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.PrintWriter;
import java.io.StringWriter;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mozilla.jss.netscape.security.util.Cert;

import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.util.JSONSerializer;

public class CertDataTest {

    private static CertData before = new CertData();
    private static StringWriter sw = new StringWriter();
    private static PrintWriter out = new PrintWriter(sw, true);

    @BeforeAll
    public static void setUpBefore() {
        out.println(Cert.HEADER);
        out.println("MIIB/zCCAWgCCQCtpWH58pqsejANBgkqhkiG9w0BAQUFADBEMRQwEgYDVQQKDAtF");
        out.println("WEFNUExFLUNPTTEYMBYGCgmSJomT8ixkAQEMCHRlc3R1c2VyMRIwEAYDVQQDDAlU");
        out.println("ZXN0IFVzZXIwHhcNMTIwNTE0MTcxNzI3WhcNMTMwNTE0MTcxNzI3WjBEMRQwEgYD");
        out.println("VQQKDAtFWEFNUExFLUNPTTEYMBYGCgmSJomT8ixkAQEMCHRlc3R1c2VyMRIwEAYD");
        out.println("VQQDDAlUZXN0IFVzZXIwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKmmiPJp");
        out.println("Agh/gPUAZjfgJ3a8QiHvpMzZ/hZy1FVP3+2sNhCkMv+D/I8Y7AsrbJGxxvD7bTDm");
        out.println("zQYtYx2ryGyOgY7KBRxEj/IrNVHIkJMYq5G/aIU4FAzpc6ntNSwUQBYUAamfK8U6");
        out.println("Wo4Cp6rLePXIDE6sfGn3VX6IeSJ8U2V+vwtzAgMBAAEwDQYJKoZIhvcNAQEFBQAD");
        out.println("gYEAY9bjcD/7Z+oX6gsJtX6Rd79E7X5IBdOdArYzHNE4vjdaQrZw6oCxrY8ffpKC");
        out.println("0T0q5PX9I7er+hx/sQjGPMrJDEN+vFBSNrZE7sTeLRgkyiqGvChSyuG05GtGzXO4");
        out.println("bFBr+Gwk2VF2wJvOhTXU2hN8sfkkd9clzIXuL8WCDhWk1bY=");
        out.println(Cert.FOOTER);

        before.setSerialNumber(new CertId("12512514865863765114"));
        before.setIssuerDN("CN=Test User,UID=testuser,O=EXAMPLE-COM");
        before.setSubjectDN("CN=Test User,UID=testuser,O=EXAMPLE-COM");
        before.setEncoded(sw.toString());
        before.setNonce(12345l);
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        CertData afterXML = CertData.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        CertData afterJSON = JSONSerializer.fromJSON(json, CertData.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
