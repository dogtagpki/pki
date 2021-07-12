package com.netscape.certsrv.user;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class UserDataTest {

    private static UserData before = new UserData();

    @Before
    public void setUpBefore() {
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
        System.out.println("JSON (before): " + json);

        UserData afterJSON = UserData.fromJSON(json);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
