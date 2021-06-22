package com.netscape.certsrv.cert;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.request.RequestStatus;

public class CertRequestInfosTest {

    private static CertRequestInfo request = new CertRequestInfo();
    private static CertRequestInfos before = new CertRequestInfos();

    @Before
    public void setUpBefore() {
        request.setRequestType("enrollment");
        request.setRequestStatus(RequestStatus.COMPLETE);
        request.setCertRequestType("pkcs10");

        before.addEntry(request);
        before.setTotal(1);
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        CertRequestInfos afterXML = CertRequestInfos.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        CertRequestInfos afterJSON = CertRequestInfos.fromJSON(json);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
