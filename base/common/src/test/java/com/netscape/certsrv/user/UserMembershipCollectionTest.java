package com.netscape.certsrv.user;

import static org.junit.Assert.assertEquals;

import org.junit.BeforeClass;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class UserMembershipCollectionTest {

    private static UserMembershipCollection before = new UserMembershipCollection();
    private static UserMembershipData membership1 = new UserMembershipData();
    private static UserMembershipData membership2 = new UserMembershipData();

    @BeforeClass
    public static void setUpBefore() {
        membership1.setID("Group 1");
        membership1.setUserID("User 1");
        before.addEntry(membership1);

        membership2.setID("Group 2");
        membership2.setUserID("User 1");
        before.addEntry(membership2);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        UserMembershipCollection afterJSON = JSONSerializer.fromJSON(json, UserMembershipCollection.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
