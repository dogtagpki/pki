package com.netscape.certsrv.property;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class DescriptorTest {

    public static Logger logger = LoggerFactory.getLogger(DescriptorTest.class);

    private static Descriptor before = new Descriptor(
            IDescriptor.CHOICE,
            "true,false,-",
            "-",
            "CMS_PROFILE_CRITICAL");

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        Descriptor afterJSON = JSONSerializer.fromJSON(json, Descriptor.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }
}
