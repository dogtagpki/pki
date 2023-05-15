package com.netscape.certsrv.key;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.util.JSONSerializer;

public class KeyRequestResponseTest {

    private static KeyRequestResponse before = new KeyRequestResponse();
    private static KeyRequestInfo requestInfo = new KeyRequestInfo();
    private static KeyData keyData = new KeyData();

    @BeforeAll
    public static void setUpBefore() {
        requestInfo.setRequestID(new RequestId("0x1"));
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
        assertEquals(before, afterJSON);
    }

}
