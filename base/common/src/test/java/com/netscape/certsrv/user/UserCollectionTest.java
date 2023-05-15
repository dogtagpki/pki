package com.netscape.certsrv.user;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class UserCollectionTest {

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
        System.out.println("JSON (before): " + json);

        UserCollection afterJSON = JSONSerializer.fromJSON(json, UserCollection.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
