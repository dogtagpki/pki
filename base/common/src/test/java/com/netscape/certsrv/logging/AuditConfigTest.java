package com.netscape.certsrv.logging;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Map;
import java.util.TreeMap;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class AuditConfigTest {

    public static Logger logger = LoggerFactory.getLogger(AuditConfigTest.class);

    private static AuditConfig before = new AuditConfig();
    private static Map<String, String> eventConfigs = new TreeMap<>();


    @BeforeAll
    public static void setUpBefore() {
        before.setStatus("Enabled");
        before.setSigned(false);
        before.setInterval(10);
        before.setBufferSize(512);

        eventConfigs.put("event1", "mandatory");
        eventConfigs.put("event2", "enabled");
        eventConfigs.put("event3", "disabled");
        before.setEventConfigs(eventConfigs);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        AuditConfig afterJSON = JSONSerializer.fromJSON(json, AuditConfig.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
