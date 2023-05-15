package com.netscape.certsrv.profile;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.util.JSONSerializer;

public class PolicyConstraintTest {

    private static PolicyConstraint before = new PolicyConstraint();
    private static PolicyConstraintValue pcv1 = new PolicyConstraintValue();
    private static PolicyConstraintValue pcv2 = new PolicyConstraintValue();
    private static Descriptor descriptor = new Descriptor(
            IDescriptor.CHOICE,
            "true,false,-",
            "-",
            "CMS_PROFILE_CRITICAL");
    private static List<PolicyConstraintValue> constraints = new ArrayList<>();

    @BeforeAll
    public static void setUpBefore() {
        before.setClassId("foo");
        pcv1.setDescriptor(descriptor);
        pcv1.setName("foo1");
        pcv1.setValue("bar1");
        constraints.add(pcv1);
        pcv2.setDescriptor(descriptor);
        pcv2.setName("foo2");
        pcv2.setValue("bar2");
        constraints.add(pcv2);
        before.setConstraints(constraints);
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
        assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        PolicyConstraint afterJSON = JSONSerializer.fromJSON(json, PolicyConstraint.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
