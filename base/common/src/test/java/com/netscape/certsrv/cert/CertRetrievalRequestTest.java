package com.netscape.certsrv.cert;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.util.JSONSerializer;

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
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        CertRetrievalRequest afterJSON = JSONSerializer.fromJSON(json, CertRetrievalRequest.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
