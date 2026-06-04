package com.netscape.certsrv.user;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class UserMembershipCollectionTest {

    public static Logger logger = LoggerFactory.getLogger(UserMembershipCollectionTest.class);

    private static UserMembershipCollection before = new UserMembershipCollection();
    private static UserMembershipData membership1 = new UserMembershipData();
    private static UserMembershipData membership2 = new UserMembershipData();

    @BeforeAll
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
        logger.debug("JSON (before): " + json);

        UserMembershipCollection afterJSON = JSONSerializer.fromJSON(json, UserMembershipCollection.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
