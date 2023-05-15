package com.netscape.certsrv.cert;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Date;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mozilla.jss.netscape.security.x509.RevocationReason;

import com.netscape.certsrv.util.JSONSerializer;

public class CertRevokeRequestTest {

    private static CertRevokeRequest before = new CertRevokeRequest();

    @BeforeAll
    public static void setUpBefore() {
        before.setReason(RevocationReason.CERTIFICATE_HOLD.getLabel());
        before.setInvalidityDate(new Date());
        before.setComments("test");
        before.setEncoded("test");
        before.setNonce(12345l);
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        CertRevokeRequest afterXML = CertRevokeRequest.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        CertRevokeRequest afterJSON = JSONSerializer.fromJSON(json, CertRevokeRequest.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
