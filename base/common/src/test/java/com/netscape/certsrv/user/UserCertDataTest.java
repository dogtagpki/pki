//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.certsrv.user;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.PrintWriter;
import java.io.StringWriter;

import org.junit.jupiter.api.Test;
import org.mozilla.jss.netscape.security.util.Cert;

import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.util.JSONSerializer;

public class UserCertDataTest {

    UserCertData userCertData;

    public UserCertDataTest() {

        StringWriter sw = new StringWriter();
        PrintWriter out = new PrintWriter(sw, true);

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

        userCertData = new UserCertData();
        userCertData.setVersion(1);
        userCertData.setSerialNumber(new CertId("12512514865863765114"));
        userCertData.setIssuerDN("CN=Test User,UID=testuser,O=EXAMPLE");
        userCertData.setSubjectDN("CN=Test User,UID=testuser,O=EXAMPLE");
        userCertData.setEncoded(sw.toString());
    }

    @Test
    public void testJSON() throws Exception {

        String json = userCertData.toJSON();
        System.out.println("Before: " + json);

        UserCertData after = JSONSerializer.fromJSON(json, UserCertData.class);
        System.out.println("After: " + after.toJSON());

        assertEquals(userCertData, after);
    }
}
