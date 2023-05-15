package com.netscape.certsrv.group;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class GroupMemberCollectionTest {


    private static GroupMemberCollection before = new GroupMemberCollection();
    private static GroupMemberData member1 = new GroupMemberData();
    private static GroupMemberData member2 = new GroupMemberData();

    @BeforeAll
    public static void setUpBefore() {
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

        GroupMemberCollection afterJSON = JSONSerializer.fromJSON(json, GroupMemberCollection.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
