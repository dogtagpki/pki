package com.netscape.certsrv.cert;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Date;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.util.JSONSerializer;

public class CertDataInfoTest {

    public static Logger logger = LoggerFactory.getLogger(CertDataInfoTest.class);

    private static CertDataInfo before = new CertDataInfo();

    @BeforeAll
    public static void setUpBefore() {
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
        logger.debug("XML (before): " + xml);

        CertDataInfo afterXML = CertDataInfo.fromXML(xml);
        logger.debug("XML (after): " + afterXML.toXML());

        // Assert
        assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        CertDataInfo afterJSON = JSONSerializer.fromJSON(json, CertDataInfo.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
