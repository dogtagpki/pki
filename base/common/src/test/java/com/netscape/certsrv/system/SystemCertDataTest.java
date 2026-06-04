package com.netscape.certsrv.system;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class SystemCertDataTest {

    public static Logger logger = LoggerFactory.getLogger(SystemCertDataTest.class);

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
        logger.debug("JSON (before): " + json);

        SystemCertData afterJSON = JSONSerializer.fromJSON(json, SystemCertData.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
