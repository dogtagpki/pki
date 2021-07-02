package com.netscape.certsrv.profile;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.util.JSONSerializer;

public class PolicyConstraintValueTest {

    private static PolicyConstraintValue before = new PolicyConstraintValue();
    private static Descriptor descriptor = new Descriptor(
            IDescriptor.CHOICE,
            "true,false,-",
            "-",
            "CMS_PROFILE_CRITICAL");

    @Before
    public void setUpBefore() {
        before.setDescriptor(descriptor);
        before.setName("foo");
        before.setValue("bar");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        PolicyConstraintValue afterJSON =
                JSONSerializer.fromJSON(json, PolicyConstraintValue.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
