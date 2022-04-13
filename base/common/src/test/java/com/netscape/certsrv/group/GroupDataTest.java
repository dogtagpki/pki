package com.netscape.certsrv.group;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class GroupDataTest {

    private static GroupData before = new GroupData();

    @Before
    public void setUpBefore() {
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
        Assert.assertEquals(before, afterJSON);
    }

}
