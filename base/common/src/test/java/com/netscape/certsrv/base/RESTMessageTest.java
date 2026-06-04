package com.netscape.certsrv.base;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class RESTMessageTest {

    public static Logger logger = LoggerFactory.getLogger(RESTMessageTest.class);

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
        logger.debug("XML (before): " + xml);

        RESTMessage afterXML = RESTMessage.fromXML(xml);
        logger.debug("XML (after): " + afterXML.toXML());

        // Assert
        assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        RESTMessage afterJSON = JSONSerializer.fromJSON(json, RESTMessage.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
