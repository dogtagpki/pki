package com.netscape.certsrv.profile;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.util.JSONSerializer;

public class ProfileAttributeTest {

    private static ProfileAttribute before = new ProfileAttribute();

    @Before
    public void setUpBefore() {
        before.setDescriptor(new Descriptor());
        before.setName("foo");
        before.setValue("bar");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        ProfileAttribute afterJSON = JSONSerializer.fromJSON(json, ProfileAttribute.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
