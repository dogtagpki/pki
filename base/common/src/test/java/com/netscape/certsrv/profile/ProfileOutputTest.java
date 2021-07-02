package com.netscape.certsrv.profile;

import java.util.ArrayList;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class ProfileOutputTest {

    private static ProfileOutput before = new ProfileOutput();

    @Before
    public void setUpBefore() {
        before.setAttrs(new ArrayList<>());
        before.setName("foo");
        before.setClassId("bar");
        before.setId("lorem");
        before.setText("ipsum");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        ProfileOutput afterJSON = JSONSerializer.fromJSON(json, ProfileOutput.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
