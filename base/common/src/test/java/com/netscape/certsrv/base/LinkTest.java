package com.netscape.certsrv.base;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class LinkTest {

    private static Link before = new Link();

    @Before
    public void setUpBefore() {
        before.setHref("http://example.com");
        before.setRelationship("next");
        before.setType("application/json");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        Link afterJSON = JSONSerializer.fromJSON(json, Link.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
