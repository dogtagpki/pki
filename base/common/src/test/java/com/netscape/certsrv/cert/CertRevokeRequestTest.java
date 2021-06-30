package com.netscape.certsrv.cert;

import java.util.Date;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class CertRevokeRequestTest {

    private static CertRevokeRequest before = new CertRevokeRequest();

    @Before
    public void setUpBefore() {
    //  before.setReason(RevocationReason.CERTIFICATE_HOLD);
        before.setInvalidityDate(new Date());
        before.setComments("test");
        before.setEncoded("test");
        before.setNonce(12345l);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        CertRevokeRequest afterJSON = JSONSerializer.fromJSON(json, CertRevokeRequest.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
