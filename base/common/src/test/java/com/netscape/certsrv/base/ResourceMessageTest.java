package com.netscape.certsrv.base;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class ResourceMessageTest {

    private static ResourceMessage before = new ResourceMessage();

    @Before
    public void setUpBefore() {
        before.setClassName(ResourceMessage.class.getName());
        before.setAttribute("attr1", "value1");
        before.setAttribute("attr2", "value2");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        ResourceMessage afterJSON = JSONSerializer.fromJSON(json, ResourceMessage.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
