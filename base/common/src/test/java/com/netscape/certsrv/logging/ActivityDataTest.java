package com.netscape.certsrv.logging;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Date;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class ActivityDataTest {

    public static Logger logger = LoggerFactory.getLogger(ActivityDataTest.class);

    private static ActivityData before = new ActivityData();

    @BeforeAll
    public static void setUpBefore() {
        before.setID("activity1");
        before.setTokenID("TOKEN1234");
        before.setUserID("user1");
        before.setIP("192.168.1.1");
        before.setOperation("enroll");
        before.setResult("success");
        before.setMessage("test");
        before.setDate(new Date());
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        ActivityData afterJSON = JSONSerializer.fromJSON(json, ActivityData.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
