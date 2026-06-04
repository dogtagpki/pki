package com.netscape.certsrv.system;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class SecurityDomainHostTest {

    public static Logger logger = LoggerFactory.getLogger(SecurityDomainHostTest.class);

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
        logger.debug("JSON (before): " + json);

        SecurityDomainHost afterJSON = JSONSerializer.fromJSON(json, SecurityDomainHost.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
