package com.netscape.certsrv.profile;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class ProfileDataInfoTest {

    public static Logger logger = LoggerFactory.getLogger(ProfileDataInfoTest.class);

    private static ProfileDataInfo before = new ProfileDataInfo();

    @BeforeAll
    public static void setUpBefore() {
        before.setProfileDescription("foo");
        before.setProfileId("bar");
        before.setProfileName("lorem");
        before.setProfileURL("https://www.example.com");
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        logger.debug("XML (before): " + xml);

        ProfileDataInfo afterXML = ProfileDataInfo.fromXML(xml);
        logger.debug("XML (after): " + afterXML.toXML());

        // Assert
        assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        ProfileDataInfo afterJSON = JSONSerializer.fromJSON(json, ProfileDataInfo.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
