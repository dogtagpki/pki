package com.netscape.certsrv.profile;

import java.util.ArrayList;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class PolicyDefaultTest {

    private static PolicyDefault before = new PolicyDefault();

    @Before
    public void setUpBefore() {
        before.setAttributes(new ArrayList<>());
        before.setClassId("foo");
        before.setName("bar");
        before.setParams(new ArrayList<>());
        before.setText("lorem");
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        PolicyDefault afterXML = PolicyDefault.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        PolicyDefault afterJSON = JSONSerializer.fromJSON(json, PolicyDefault.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
