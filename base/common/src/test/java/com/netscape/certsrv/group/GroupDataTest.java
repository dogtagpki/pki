package com.netscape.certsrv.group;

import java.net.URI;
import java.net.URISyntaxException;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.base.Link;
import com.netscape.certsrv.util.JSONSerializer;

public class GroupDataTest {

    private static GroupData before = new GroupData();

    @Before
    public void setUpBefore() throws URISyntaxException {
        before.setDescription("Test GroupData");
        before.setID("foo");
        before.setGroupID("bar");
        before.setLink(new Link("self", new URI("https://www.example.com")));
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
