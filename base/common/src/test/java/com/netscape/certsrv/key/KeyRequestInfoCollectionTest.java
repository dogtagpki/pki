package com.netscape.certsrv.key;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.util.JSONSerializer;

public class KeyRequestInfoCollectionTest {

    public static Logger logger = LoggerFactory.getLogger(KeyRequestInfoCollectionTest.class);

    private static KeyRequestInfoCollection before = new KeyRequestInfoCollection();
    private static KeyRequestInfo request = new KeyRequestInfo();

    @BeforeAll
    public static void setUpBefore() {
        request.setRequestID(new RequestId("0x1"));
        request.setRequestType("securityDataEnrollment");
        before.addEntry(request);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        KeyRequestInfoCollection afterJSON =
                JSONSerializer.fromJSON(json, KeyRequestInfoCollection.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
