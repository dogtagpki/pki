package com.netscape.certsrv.system;

import java.util.ArrayList;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class CertificateSetupResponseTest {

    private static CertificateSetupResponse before = new CertificateSetupResponse();

    @Before
    public void setUpBefore() {
        before.setSystemCerts(new ArrayList<>());
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        CertificateSetupResponse afterXML = CertificateSetupResponse.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        CertificateSetupResponse afterJSON =
                JSONSerializer.fromJSON(json, CertificateSetupResponse.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
