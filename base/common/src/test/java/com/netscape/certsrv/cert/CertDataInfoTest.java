package com.netscape.certsrv.cert;

import java.util.Date;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.util.JSONSerializer;

public class CertDataInfoTest {

    private static CertDataInfo before = new CertDataInfo();

    @Before
    public void setUpBefore() {
        before.setID(new CertId("12512514865863765114"));
        before.setSubjectDN("CN=Test User,UID=testuser,O=EXAMPLE-COM");
        before.setIssuerDN("CN=Certificate Authority,O=EXAMPLE-COM");
        before.setStatus("VALID");
        before.setType("X.509");
        before.setVersion(2);
        before.setKeyAlgorithmOID("1.2.840.113549.1.1.1");
        before.setKeyLength(2048);
        before.setNotValidBefore(new Date());
        before.setNotValidAfter(new Date());
        before.setIssuedOn(new Date());
        before.setIssuedBy("admin");
        before.setRevokedOn(new Date());
        before.setRevokedBy("admin");
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        CertDataInfo afterXML = CertDataInfo.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        CertDataInfo afterJSON = JSONSerializer.fromJSON(json, CertDataInfo.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
