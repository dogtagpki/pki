package com.netscape.certsrv.cert;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.certsrv.util.JSONSerializer;

public class CertRequestInfoTest {

    private static CertRequestInfo before = new CertRequestInfo();

    @Before
    public void setUpBefore() {
        before.setRequestType("enrollment");
        before.setRequestStatus(RequestStatus.COMPLETE);
        before.setCertRequestType("pkcs10");
        before.setCertId(new CertId("5"));
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        CertRequestInfo afterJSON = JSONSerializer.fromJSON(json, CertRequestInfo.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
