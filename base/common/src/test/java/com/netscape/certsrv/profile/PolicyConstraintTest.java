package com.netscape.certsrv.profile;

import java.util.ArrayList;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class PolicyConstraintTest {

    private static PolicyConstraint before = new PolicyConstraint();

    @Before
    public void setUpBefore() {
        before.setClassId("foo");
        before.setConstraints(new ArrayList<>());
        before.setName("bar");
        before.setText("lorem ipsum");
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        PolicyConstraint afterXML = PolicyConstraint.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        PolicyConstraint afterJSON = JSONSerializer.fromJSON(json, PolicyConstraint.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
