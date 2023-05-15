package com.netscape.certsrv.user;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class UserMembershipDataTest {

    private static UserMembershipData before = new UserMembershipData();

    @BeforeAll
    public static void setUpBefore() {
        before.setID("Group 1");
        before.setUserID("User 1");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        UserMembershipData afterJSON = JSONSerializer.fromJSON(json, UserMembershipData.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
