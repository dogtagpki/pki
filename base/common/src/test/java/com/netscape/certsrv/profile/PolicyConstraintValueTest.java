package com.netscape.certsrv.profile;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.util.JSONSerializer;

public class PolicyConstraintValueTest {

    public static Logger logger = LoggerFactory.getLogger(PolicyConstraintValueTest.class);

    private static PolicyConstraintValue before = new PolicyConstraintValue();
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

        PolicyConstraintValue afterXML = PolicyConstraintValue.fromXML(xml);
        logger.debug("XML (after): " + afterXML.toXML());

        // Assert
        assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        PolicyConstraintValue afterJSON =
                JSONSerializer.fromJSON(json, PolicyConstraintValue.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
