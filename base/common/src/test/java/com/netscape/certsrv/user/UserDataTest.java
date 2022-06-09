package com.netscape.certsrv.user;

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

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

        UserData afterJSON = JSONSerializer.fromJSON(json, UserData.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
