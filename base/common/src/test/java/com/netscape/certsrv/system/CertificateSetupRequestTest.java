package com.netscape.certsrv.system;

import java.net.MalformedURLException;
import java.net.URL;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class CertificateSetupRequestTest {

    private static CertificateSetupRequest before = new CertificateSetupRequest();

    @Before
    public void setUpBefore() throws MalformedURLException {
        before.setClone(true);
        before.setInstallToken(new InstallToken("foo"));
        before.setMasterURL(new URL("https://www.example.com"));
        before.setPin("bar");
        before.setSystemCert(new SystemCertData());
        before.setTag("lorem");
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        CertificateSetupRequest afterXML = CertificateSetupRequest.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        CertificateSetupRequest afterJSON = CertificateSetupRequest.fromJSON(json);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
