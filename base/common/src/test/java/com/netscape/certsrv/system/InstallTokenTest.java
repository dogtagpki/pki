package com.netscape.certsrv.system;

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class InstallTokenTest {

    private static InstallToken before = new InstallToken();

    @Before
    public void setUpBefore() {
        before.setToken("foo");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        InstallToken afterJSON = JSONSerializer.fromJSON(json, InstallToken.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
