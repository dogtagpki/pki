package com.netscape.certsrv.base;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class LinkTest {

    private static Link before = new Link();

    @Before
    public void setUpBefore() {
        before.setHref("http://example.com");
        before.setRelationship("next");
        before.setType("application/json");
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        Link afterXML = Link.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        Link afterJSON = Link.fromJSON(json);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
