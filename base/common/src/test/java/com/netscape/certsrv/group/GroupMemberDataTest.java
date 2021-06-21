package com.netscape.certsrv.group;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class GroupMemberDataTest {

    private static GroupMemberData before = new GroupMemberData();

    @Before
    public void setUpBefore() {
        before.setID("testuser");
        before.setGroupID("Test Group");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        GroupMemberData afterJSON = GroupMemberData.fromJSON(json);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }


}
