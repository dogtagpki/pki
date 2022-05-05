package com.netscape.certsrv.logging;

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class AuditFileTest {

    private static AuditFile before = new AuditFile();

    @Before
    public void setUpBefore() {
        before.setName("audit.log");
        before.setSize(1024l);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        AuditFile afterJSON = JSONSerializer.fromJSON(json, AuditFile.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
