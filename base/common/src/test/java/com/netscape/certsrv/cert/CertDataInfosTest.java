package com.netscape.certsrv.cert;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Date;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.dbs.certdb.CertId;

public class CertDataInfosTest {

    private static CertDataInfo info = new CertDataInfo();
    private static CertDataInfos before = new CertDataInfos();


    @BeforeAll
    public static void setUpBefore() {
        info.setID(new CertId("12512514865863765114"));
        info.setSubjectDN("CN=Test User,UID=testuser,O=EXAMPLE-COM");
        info.setIssuerDN("CN=Certificate Authority,O=EXAMPLE-COM");
        info.setStatus("VALID");
        info.setType("X.509");
        info.setVersion(2);
        info.setKeyAlgorithmOID("1.2.840.113549.1.1.1");
        info.setKeyLength(2048);
        info.setNotValidBefore(new Date());
        info.setNotValidAfter(new Date());
        info.setIssuedOn(new Date());
        info.setIssuedBy("admin");
        info.setRevokedOn(new Date());
        info.setRevokedBy("admin");

        before.addEntry(info);
        before.setTotal(1);
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        CertDataInfos afterXML = CertDataInfos.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        assertEquals(before, afterXML);
    }
}
