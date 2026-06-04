package com.netscape.certsrv.profile;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class ProfileParameterTest {

    public static Logger logger = LoggerFactory.getLogger(ProfileParameterTest.class);

    private static ProfileParameter before = new ProfileParameter();

    @BeforeAll
    public static void setUpBefore() {
        before.setName("foo");
        before.setValue("bar");
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        logger.debug("XML (before): " + xml);

        ProfileParameter afterXML = ProfileParameter.fromXML(xml);
        logger.debug("XML (after): " + afterXML.toXML());

        // Assert
        assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        ProfileParameter afterJSON = JSONSerializer.fromJSON(json, ProfileParameter.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
