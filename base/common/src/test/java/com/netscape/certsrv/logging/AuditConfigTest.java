package com.netscape.certsrv.logging;

import java.util.Map;
import java.util.TreeMap;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class AuditConfigTest {

    private static AuditConfig before = new AuditConfig();
    private static Map<String, String> eventConfigs = new TreeMap<>();


    @Before
    public void setUpBefore() {
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
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        AuditConfig afterXML = AuditConfig.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        AuditConfig afterJSON = JSONSerializer.fromJSON(json, AuditConfig.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
