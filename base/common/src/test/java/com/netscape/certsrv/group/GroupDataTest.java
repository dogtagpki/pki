package com.netscape.certsrv.group;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class GroupDataTest {

    public static Logger logger = LoggerFactory.getLogger(GroupDataTest.class);

    private static GroupData before = new GroupData();

    @BeforeAll
    public static void setUpBefore() {
        before.setDescription("Test GroupData");
        before.setID("foo");
        before.setGroupID("bar");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        GroupData afterJSON = JSONSerializer.fromJSON(json, GroupData.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
