package com.netscape.certsrv.group;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class GroupDataTest {

    private static GroupData before = new GroupData();

    @BeforeAll
    public static void setUpBefore() {
        before.setDescription("Test GroupData");
        before.setID("foo");
        before.setGroupID("bar");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        GroupData afterJSON = JSONSerializer.fromJSON(json, GroupData.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
