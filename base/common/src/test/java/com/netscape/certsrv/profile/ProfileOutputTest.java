package com.netscape.certsrv.profile;

import java.util.ArrayList;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class ProfileOutputTest {

    private static ProfileOutput before = new ProfileOutput();

    @Before
    public void setUpBefore() {
        before.setAttrs(new ArrayList<>());
        before.setName("foo");
        before.setClassId("bar");
        before.setId("lorem");
        before.setText("ipsum");
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        ProfileOutput afterXML = ProfileOutput.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        ProfileOutput afterJSON = ProfileOutput.fromJSON(json);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
