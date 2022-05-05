package com.netscape.certsrv.key;

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.certsrv.util.JSONSerializer;

public class KeyRequestInfoTest {

    private static KeyRequestInfo before = new KeyRequestInfo();

    @Before
    public void setUpBefore() {
        before.setRequestID(new RequestId("0x1"));
        before.setRequestType("securityDataEnrollment");
        before.setRequestStatus(RequestStatus.COMPLETE);
        before.setKeyURL("https://localhost:8443/kra/rest/agent/keys/123");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        KeyRequestInfo afterJSON = JSONSerializer.fromJSON(json, KeyRequestInfo.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
