package com.netscape.certsrv.group;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class GroupMemberCollectionTest {


    private static GroupMemberCollection before = new GroupMemberCollection();
    private static GroupMemberData member1 = new GroupMemberData();
    private static GroupMemberData member2 = new GroupMemberData();

    @Before
    public void setUpBefore() {
        member1.setID("User 1");
        member1.setGroupID("Group 1");
        before.addEntry(member1);

        member2.setID("User 2");
        member2.setGroupID("Group 1");
        before.addEntry(member2);

        before.setTotal(2);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        GroupMemberCollection afterJSON = GroupMemberCollection.fromJSON(json);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
