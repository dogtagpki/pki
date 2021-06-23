package com.netscape.certsrv.profile;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class ProfilePolicyTest {

    private static ProfilePolicy before = new ProfilePolicy();

    @Before
    public void setUpBefore() {
        before.setConstraint(new PolicyConstraint());
        before.setDef(new PolicyDefault());
        before.setId("foo");
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        ProfilePolicy afterXML = ProfilePolicy.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        ProfilePolicy afterJSON = ProfilePolicy.fromJSON(json);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
