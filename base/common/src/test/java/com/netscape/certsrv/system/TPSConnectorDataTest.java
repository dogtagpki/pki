package com.netscape.certsrv.system;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class TPSConnectorDataTest {

    private static TPSConnectorData before = new TPSConnectorData();

    @Before
    public void setUpBefore() {
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
        Assert.assertEquals(before, afterJSON);
    }

}
