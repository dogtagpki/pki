package com.netscape.certsrv.cert;

import org.junit.Assert;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class CertReviewResponseTest {

    private CertReviewResponse before = new CertReviewResponse();

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        CertReviewResponse afterJSON = JSONSerializer.fromJSON(json, CertReviewResponse.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
