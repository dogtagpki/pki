package com.netscape.certsrv.user;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class UserCollectionTest {

    public static Logger logger = LoggerFactory.getLogger(UserCollectionTest.class);

    private static UserData user = new UserData();
    private static UserCollection before = new UserCollection();


    @BeforeAll
    public static void setUpBefore() {
        user.setUserID("testuser");
        user.setFullName("Test User");
        user.setEmail("testuser@example.com");

        before.addEntry(user);
        before.setTotal(1);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        UserCollection afterJSON = JSONSerializer.fromJSON(json, UserCollection.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
