package com.netscape.certsrv.cert;

import org.junit.Assert;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class CertSearchRequestTest {

    private static CertSearchRequest before = new CertSearchRequest();

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        CertSearchRequest afterJSON = JSONSerializer.fromJSON(json, CertSearchRequest.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }


}
