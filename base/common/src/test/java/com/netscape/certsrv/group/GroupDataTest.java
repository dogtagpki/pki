package com.netscape.certsrv.group;

import java.net.URI;
import java.net.URISyntaxException;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.base.Link;

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
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        GroupData afterXML = GroupData.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        GroupData afterJSON = GroupData.fromJSON(json);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
