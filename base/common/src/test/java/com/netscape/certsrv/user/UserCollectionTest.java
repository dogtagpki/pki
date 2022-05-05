package com.netscape.certsrv.user;

import static org.junit.Assert.assertEquals;

import org.junit.BeforeClass;
import org.junit.Test;

public class UserCollectionTest {

    private static UserData user = new UserData();
    private static UserCollection before = new UserCollection();


    @BeforeClass
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

        UserCollection afterJSON = UserCollection.fromJSON(json);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
