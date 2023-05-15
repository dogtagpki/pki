package com.netscape.certsrv.system;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class SystemCertDataTest {

    private static SystemCertData before = new SystemCertData();
    private static String[] dnsNames = {"lorem, ipsum"};

    @BeforeAll
    public static void setUpBefore() {
        before.setCert("foo");
        before.setProfile("sit");
        before.setToken("elit");
        before.setType("sed");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        SystemCertData afterJSON = JSONSerializer.fromJSON(json, SystemCertData.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
