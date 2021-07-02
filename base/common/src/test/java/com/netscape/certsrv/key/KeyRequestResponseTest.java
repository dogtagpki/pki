package com.netscape.certsrv.key;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

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
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        KeyRequestResponse afterJSON = JSONSerializer.fromJSON(json, KeyRequestResponse.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
