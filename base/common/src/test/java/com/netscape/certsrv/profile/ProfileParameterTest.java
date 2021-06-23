package com.netscape.certsrv.profile;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class ProfileParameterTest {

    private static ProfileParameter before = new ProfileParameter();

    @Before
    public void setUpBefore() {
        before.setName("foo");
        before.setValue("bar");
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        ProfileParameter afterXML = ProfileParameter.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        ProfileParameter afterJSON = ProfileParameter.fromJSON(json);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
