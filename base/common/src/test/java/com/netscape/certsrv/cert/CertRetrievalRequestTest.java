package com.netscape.certsrv.cert;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.request.RequestId;

public class CertRetrievalRequestTest {

    private static CertRetrievalRequest before = new CertRetrievalRequest();
    private static CertId cId = new CertId(0x3);
    private static RequestId rId = new RequestId(0x3);


    @Before
    public void setUpBefore() {
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
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        CertRetrievalRequest afterJSON = CertRetrievalRequest.fromJSON(json);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
