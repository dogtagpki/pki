package com.netscape.certsrv.profile;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.property.Descriptor;

public class PolicyConstraintValueTest {

    private static PolicyConstraintValue before = new PolicyConstraintValue();

    @Before
    public void setUpBefore() {
        before.setDescriptor(new Descriptor());
        before.setName("foo");
        before.setValue("bar");
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        PolicyConstraintValue afterXML = PolicyConstraintValue.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        PolicyConstraintValue afterJSON = PolicyConstraintValue.fromJSON(json);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
