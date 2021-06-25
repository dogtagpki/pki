package com.netscape.certsrv.request;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class CMSRequestInfoTest {

    private static CMSRequestInfo before = new CMSRequestInfo();

    @Before
    public void setUpBefore() {
        before.setRequestType("securityDataEnrollment");
        before.setRequestStatus(RequestStatus.COMPLETE);
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        CMSRequestInfo afterXML = CMSRequestInfo.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        CMSRequestInfo afterJSON = JSONSerializer.fromJSON(json, CMSRequestInfo.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
