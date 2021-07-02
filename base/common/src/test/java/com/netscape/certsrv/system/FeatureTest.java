package com.netscape.certsrv.system;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class FeatureTest {

    private static Feature before = new Feature();

    @Before
    public void setUpBefore() {
        before.setId("authority");
        before.setEnabled(true);
        before.setDescription("Subordinate CA Feature");
        before.setVersion("1.0");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        Feature afterJSON = JSONSerializer.fromJSON(json, Feature.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
