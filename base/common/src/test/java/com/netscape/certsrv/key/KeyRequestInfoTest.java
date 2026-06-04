package com.netscape.certsrv.key;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.certsrv.util.JSONSerializer;

public class KeyRequestInfoTest {

    public static Logger logger = LoggerFactory.getLogger(KeyRequestInfoTest.class);

    private static KeyRequestInfo before = new KeyRequestInfo();

    @BeforeAll
    public static void setUpBefore() {
        before.setRequestID(new RequestId("0x1"));
        before.setRequestType("securityDataEnrollment");
        before.setRequestStatus(RequestStatus.COMPLETE);
        before.setKeyURL("https://localhost:8443/kra/rest/agent/keys/123");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        KeyRequestInfo afterJSON = JSONSerializer.fromJSON(json, KeyRequestInfo.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
