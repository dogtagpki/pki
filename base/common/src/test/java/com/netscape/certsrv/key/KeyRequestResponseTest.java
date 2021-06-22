package com.netscape.certsrv.key;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class KeyRequestResponseTest {

    private static KeyRequestResponse before = new KeyRequestResponse();
    private static KeyRequestInfo requestInfo = new KeyRequestInfo();
    private static KeyData keyData = new KeyData();

    @Before
    public void setUpBefore() {
        requestInfo.setRequestType("test");
        before.setRequestInfo(requestInfo);

        keyData.setAlgorithm("AES");
        before.setKeyData(keyData);
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        KeyRequestResponse afterXML = KeyRequestResponse.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        KeyRequestResponse afterJSON = KeyRequestResponse.fromJSON(json);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
