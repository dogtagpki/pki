package org.dogtagpki.common;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.TreeMap;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.base.Link;

public class ConfigDataTest {

    private static ConfigData before = new ConfigData();
    private static Map<String, String> properties = new TreeMap<>();

    @Before
    public void setUpBefore() throws URISyntaxException {
        properties.put("param1", "value1");
        properties.put("param2", "value2");

        before.setLink(new Link("self", new URI("https://www.example.com")));
        before.setProperties(properties);
        before.setStatus("ENABLED");
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        ConfigData afterXML = ConfigData.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        ConfigData afterJSON = ConfigData.fromJSON(json);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
