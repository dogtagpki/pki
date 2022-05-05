package com.netscape.certsrv.key;

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.util.JSONSerializer;

public class KeyRequestInfoCollectionTest {

    private static KeyRequestInfoCollection before = new KeyRequestInfoCollection();
    private static KeyRequestInfo request = new KeyRequestInfo();

    @Before
    public void setUpBefore() {
        request.setRequestID(new RequestId("0x1"));
        request.setRequestType("securityDataEnrollment");
        before.addEntry(request);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        KeyRequestInfoCollection afterJSON =
                JSONSerializer.fromJSON(json, KeyRequestInfoCollection.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
