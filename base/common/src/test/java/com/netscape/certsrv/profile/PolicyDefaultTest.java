package com.netscape.certsrv.profile;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.util.JSONSerializer;

public class PolicyDefaultTest {

    private static PolicyDefault before = new PolicyDefault();
    private static ProfileParameter pp1 = new ProfileParameter();
    private static ProfileParameter pp2 = new ProfileParameter();
    private static List<ProfileParameter> params = new ArrayList<>();
    private static ProfileAttribute pa1 = new ProfileAttribute();
    private static ProfileAttribute pa2 = new ProfileAttribute();
    private static List<ProfileAttribute> attributes = new ArrayList<>();
    private static Descriptor descriptor = new Descriptor(
            IDescriptor.CHOICE,
            "true,false,-",
            "-",
            "CMS_PROFILE_CRITICAL");

    @BeforeAll
    public static void setUpBefore() {
        pa1.setDescriptor(descriptor);
        pa1.setName("spam1");
        pa1.setValue("ham1");
        attributes.add(pa1);
        pa2.setDescriptor(descriptor);
        pa2.setName("spam2");
        pa2.setValue("ham2");
        attributes.add(pa2);
        before.setAttributes(attributes);

        before.setClassId("foo");
        before.setName("bar");

        pp1.setName("foo1");
        pp1.setValue("bar1");
        params.add(pp1);
        pp2.setName("foo2");
        pp2.setValue("bar2");
        params.add(pp2);
        before.setParams(params);

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
        assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        PolicyDefault afterJSON = JSONSerializer.fromJSON(json, PolicyDefault.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
