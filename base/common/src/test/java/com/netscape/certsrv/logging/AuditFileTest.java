package com.netscape.certsrv.logging;

import org.junit.Assert;
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
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        AuditFile afterXML = AuditFile.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        AuditFile afterJSON = JSONSerializer.fromJSON(json, AuditFile.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
