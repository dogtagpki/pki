package com.netscape.certsrv.profile;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.util.JSONSerializer;

public class ProfileAttributeTest {

    public static Logger logger = LoggerFactory.getLogger(ProfileAttributeTest.class);

    private static ProfileAttribute before = new ProfileAttribute();
    private static Descriptor descriptor = new Descriptor(
            IDescriptor.CHOICE,
            "true,false,-",
            "-",
            "CMS_PROFILE_CRITICAL");

    @BeforeAll
    public static void setUpBefore() {
        before.setDescriptor(descriptor);
        before.setName("foo");
        before.setValue("bar");
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        logger.debug("XML (before): " + xml);

        ProfileAttribute afterXML = ProfileAttribute.fromXML(xml);
        logger.debug("XML (after): " + afterXML.toXML());

        // Assert
        assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        ProfileAttribute afterJSON = JSONSerializer.fromJSON(json, ProfileAttribute.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
