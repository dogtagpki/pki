package com.netscape.certsrv.system;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.MalformedURLException;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class CertificateSetupRequestTest {

    private static CertificateSetupRequest before = new CertificateSetupRequest();

    @BeforeAll
    public static void setUpBefore() throws MalformedURLException {
        before.setPin("bar");
        before.setSystemCert(new SystemCertData());
        before.setTag("lorem");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        CertificateSetupRequest afterJSON =
                JSONSerializer.fromJSON(json, CertificateSetupRequest.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
