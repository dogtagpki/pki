package com.netscape.certsrv.base;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class ResourceMessageTest {

    private static ResourceMessage before = new ResourceMessage();

    @Before
    public void setUpBefore() {
        before.setClassName(ResourceMessage.class.getName());
        before.setAttribute("attr1", "value1");
        before.setAttribute("attr2", "value2");
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = ResourceMessage.marshal(before, ResourceMessage.class);
        System.out.println("XML (before): " + xml);

        ResourceMessage afterXML = ResourceMessage.unmarshal(xml, ResourceMessage.class);
        System.out.println("XML (after): " + ResourceMessage.marshal(afterXML, ResourceMessage.class));

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        ResourceMessage afterJSON = ResourceMessage.fromJSON(json);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
