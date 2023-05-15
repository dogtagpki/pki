package com.netscape.certsrv.base;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class RESTMessageTest {

    private static RESTMessage before = new RESTMessage();

    @BeforeAll
    public static void setUpBefore() {
        before.setClassName(RESTMessage.class.getName());
        before.setAttribute("attr1", "value1");
        before.setAttribute("attr2", "value2");
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        RESTMessage afterXML = RESTMessage.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        RESTMessage afterJSON = JSONSerializer.fromJSON(json, RESTMessage.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
