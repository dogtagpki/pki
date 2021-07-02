package com.netscape.certsrv.user;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class UserMembershipDataTest {

    private static UserMembershipData before = new UserMembershipData();

    @Before
    public void setUpBefore() {
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
        Assert.assertEquals(before, afterJSON);
    }

}
