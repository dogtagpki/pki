package com.netscape.certsrv.request;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class CMSRequestInfoTest {

    public static Logger logger = LoggerFactory.getLogger(CMSRequestInfoTest.class);

    private static CMSRequestInfo before = new CMSRequestInfo();

    @BeforeAll
    public static void setUpBefore() {
        before.setRequestType("securityDataEnrollment");
        before.setRequestStatus(RequestStatus.COMPLETE);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        CMSRequestInfo afterJSON = JSONSerializer.fromJSON(json, CMSRequestInfo.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
