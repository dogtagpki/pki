package com.netscape.certsrv.system;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class TPSConnectorDataTest {

    private static TPSConnectorData before = new TPSConnectorData();

    @BeforeAll
    public static void setUpBefore() {
        before.setID("tps0");
        before.setUserID("user1");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        TPSConnectorData afterJSON = JSONSerializer.fromJSON(json, TPSConnectorData.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
