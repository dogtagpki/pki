package com.netscape.certsrv.system;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class SecurityDomainHostTest {

    private static SecurityDomainHost before = new SecurityDomainHost();

    @BeforeAll
    public static void setUpBefore() {
        before.setId("CA localhost 8443");
        before.setHostname("localhost");
        before.setPort("8080");
        before.setSecurePort("8443");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        SecurityDomainHost afterJSON = JSONSerializer.fromJSON(json, SecurityDomainHost.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
