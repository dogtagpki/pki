package com.netscape.certsrv.group;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class GroupMemberDataTest {

    public static Logger logger = LoggerFactory.getLogger(GroupMemberDataTest.class);

    private static GroupMemberData before = new GroupMemberData();

    @BeforeAll
    public static void setUpBefore() {
        before.setID("testuser");
        before.setGroupID("Test Group");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        GroupMemberData afterJSON = JSONSerializer.fromJSON(json, GroupMemberData.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }


}
