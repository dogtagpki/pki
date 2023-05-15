package com.netscape.certsrv.system;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class SecurityDomainSubsystemTest {

    private static SecurityDomainSubsystem before = new SecurityDomainSubsystem();
    private static SecurityDomainHost host = new SecurityDomainHost();

    @BeforeAll
    public static void setUpBefore() {
        before.setName("CA");

        host.setId("CA localhost 8443");
        host.setHostname("localhost");
        host.setPort("8080");
        host.setSecurePort("8443");

        before.addHost(host);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        SecurityDomainSubsystem afterJSON =
                JSONSerializer.fromJSON(json, SecurityDomainSubsystem.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
