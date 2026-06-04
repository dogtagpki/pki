package com.netscape.certsrv.user;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class UserDataTest {

    public static Logger logger = LoggerFactory.getLogger(UserDataTest.class);

    private static UserData before = new UserData();

    @BeforeAll
    public static void setUpBefore() {
        before.setID("testuser");
        before.setFullName("Test User");
        before.setEmail("testuser@example.com");
        before.setPassword("12345");
        before.setPhone("1234567890");
        before.setState("1");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        UserData afterJSON = JSONSerializer.fromJSON(json, UserData.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
