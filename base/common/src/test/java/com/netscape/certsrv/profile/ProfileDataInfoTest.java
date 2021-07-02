package com.netscape.certsrv.profile;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class ProfileDataInfoTest {

    private static ProfileDataInfo before = new ProfileDataInfo();

    @Before
    public void setUpBefore() {
        before.setProfileDescription("foo");
        before.setProfileId("bar");
        before.setProfileName("lorem");
        before.setProfileURL("https://www.example.com");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        ProfileDataInfo afterJSON = JSONSerializer.fromJSON(json, ProfileDataInfo.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
