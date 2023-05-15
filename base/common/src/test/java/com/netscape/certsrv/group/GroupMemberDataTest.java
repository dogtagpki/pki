package com.netscape.certsrv.group;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class GroupMemberDataTest {

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
        System.out.println("JSON (before): " + json);

        GroupMemberData afterJSON = JSONSerializer.fromJSON(json, GroupMemberData.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }


}
