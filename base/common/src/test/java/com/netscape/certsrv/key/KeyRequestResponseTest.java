package com.netscape.certsrv.key;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.util.JSONSerializer;

public class KeyRequestResponseTest {

    public static Logger logger = LoggerFactory.getLogger(KeyRequestResponseTest.class);

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
        logger.debug("JSON (before): " + json);

        KeyRequestResponse afterJSON = JSONSerializer.fromJSON(json, KeyRequestResponse.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
