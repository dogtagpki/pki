package com.netscape.certsrv.cert;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.util.JSONSerializer;

public class CertRetrievalRequestTest {

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
        System.out.println("XML (before): " + xml);

        CertRetrievalRequest afterXML = CertRetrievalRequest.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        CertRetrievalRequest afterJSON = JSONSerializer.fromJSON(json, CertRetrievalRequest.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
