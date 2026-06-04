package com.netscape.certsrv.cert;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.util.JSONSerializer;

public class CertRetrievalRequestTest {

    public static Logger logger = LoggerFactory.getLogger(CertRetrievalRequestTest.class);

    private static CertRetrievalRequest before = new CertRetrievalRequest();
    private static CertId cId = new CertId(0x3);
    private static RequestId rId = new RequestId(0x3);


    @BeforeAll
    public static void setUpBefore() {
        before.setCertId(cId);
        before.setRequestId(rId);
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        logger.debug("XML (before): " + xml);

        CertRetrievalRequest afterXML = CertRetrievalRequest.fromXML(xml);
        logger.debug("XML (after): " + afterXML.toXML());

        // Assert
        assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        CertRetrievalRequest afterJSON = JSONSerializer.fromJSON(json, CertRetrievalRequest.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
