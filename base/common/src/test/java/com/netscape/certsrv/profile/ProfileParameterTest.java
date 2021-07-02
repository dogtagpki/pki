package com.netscape.certsrv.profile;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class ProfileParameterTest {

    private static ProfileParameter before = new ProfileParameter();

    @Before
    public void setUpBefore() {
        before.setName("foo");
        before.setValue("bar");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        ProfileParameter afterJSON = JSONSerializer.fromJSON(json, ProfileParameter.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
