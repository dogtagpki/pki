package org.dogtagpki.common;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class InfoTest {

    private static Info before = new Info();

    @BeforeAll
    public static void setUpBefore() {
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
        assertEquals(before, afterJSON);
    }

}
