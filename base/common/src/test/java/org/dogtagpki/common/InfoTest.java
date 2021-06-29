package org.dogtagpki.common;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class InfoTest {

    private static Info before = new Info();

    @Before
    public void setUpBefore() {
        before.setName("PKI");
        before.setVersion("10.8.0");
        before.setBanner(
                "WARNING!\n" +
                "Access to this service is restricted to those individuals with " +
                "specific permissions.");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        Info afterJSON = JSONSerializer.fromJSON(json, Info.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
