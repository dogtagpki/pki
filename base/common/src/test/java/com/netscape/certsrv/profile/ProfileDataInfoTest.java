package com.netscape.certsrv.profile;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class ProfileDataInfoTest {

    private static ProfileDataInfo before = new ProfileDataInfo();

    @Before
    public void setUpBefore() {
        before.setProfileDescription("foo");
        before.setProfileId("bar");
        before.setProfileName("lorem");
        before.setProfileURL("https://www.example.com");
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        ProfileDataInfo afterXML = ProfileDataInfo.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        ProfileDataInfo afterJSON = ProfileDataInfo.fromJSON(json);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
