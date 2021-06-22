package com.netscape.certsrv.cert;

import org.junit.Assert;
import org.junit.Test;

public class CertReviewResponseTest {

    private CertReviewResponse before = new CertReviewResponse();


    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        CertReviewResponse afterXML = CertReviewResponse.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        CertReviewResponse afterJSON = CertReviewResponse.fromJSON(json);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
