package com.netscape.certsrv.cert;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class CertSearchRequestTest {

    public static Logger logger = LoggerFactory.getLogger(CertSearchRequestTest.class);

    private static CertSearchRequest before = new CertSearchRequest();

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        logger.debug("XML (before): " + xml);

        CertSearchRequest afterXML = CertSearchRequest.fromXML(xml);
        logger.debug("XML (after): " + afterXML.toXML());

        // Assert
        assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        CertSearchRequest afterJSON = JSONSerializer.fromJSON(json, CertSearchRequest.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }


}
