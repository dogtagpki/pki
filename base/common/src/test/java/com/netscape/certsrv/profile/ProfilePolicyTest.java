package com.netscape.certsrv.profile;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.util.JSONSerializer;

public class ProfilePolicyTest {

    private static ProfilePolicy before = new ProfilePolicy();
    private static PolicyDefault pd = new PolicyDefault();
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
    private static PolicyConstraint pc = new PolicyConstraint();
    private static PolicyConstraintValue pcv1 = new PolicyConstraintValue();
    private static PolicyConstraintValue pcv2 = new PolicyConstraintValue();
    private static List<PolicyConstraintValue> constraints = new ArrayList<>();

    @BeforeAll
    public static void setUpBefore() {
        pc.setClassId("pc foo");
        pcv1.setDescriptor(descriptor);
        pcv1.setName("pcv foo1");
        pcv1.setValue("pcv bar1");
        constraints.add(pcv1);
        pcv2.setDescriptor(descriptor);
        pcv2.setName("pcv foo2");
        pcv2.setValue("pcv bar2");
        constraints.add(pcv2);
        pc.setConstraints(constraints);
        pc.setName("pc bar");
        pc.setText("pc lorem ipsum");
        before.setConstraint(pc);

        pa1.setDescriptor(descriptor);
        pa1.setName("spam1");
        pa1.setValue("ham1");
        attributes.add(pa1);
        pa2.setDescriptor(descriptor);
        pa2.setName("spam2");
        pa2.setValue("ham2");
        attributes.add(pa2);
        pd.setAttributes(attributes);

        pd.setClassId("pd foo");
        pd.setName("pd bar");

        pp1.setName("pp foo1");
        pp1.setValue("pp bar1");
        params.add(pp1);
        pp2.setName("pp foo2");
        pp2.setValue("pp bar2");
        params.add(pp2);
        pd.setParams(params);

        pd.setText("pd lorem");
        before.setDef(pd);
        before.setId("foo");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        ProfilePolicy afterJSON = JSONSerializer.fromJSON(json, ProfilePolicy.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
