package com.netscape.security.extensions;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.util.Hashtable;

import netscape.security.extensions.GenericASN1Extension;
import netscape.security.x509.OIDMap;

import org.junit.Assert;
import org.junit.Test;

public class GenericASN1ExtensionTest {

    //@Test
    public void testConstructorArgs() throws Exception {
        String name1 = "testExtension1";
        String oid1 = "1.2.3.4";
        String pattern = "";
        Hashtable<String, String> config = new Hashtable<String, String>();
        GenericASN1Extension extension1 = new GenericASN1Extension(name1, oid1,
                pattern, false, config);
        Assert.assertEquals(name1, extension1.getName());
        Assert.assertNotNull(OIDMap.getClass(name1));

        String name2 = "testExtension2";
        String oid2 = "2.4.6.8";
        GenericASN1Extension extension2 = new GenericASN1Extension(name2, oid2,
                pattern, false, config);
        Assert.assertEquals(name2, extension2.getName());
        Assert.assertNotNull(OIDMap.getClass(name2));
    }

    @Test
    public void testConstructorJustConfig() throws Exception {
        String name1 = "testExtension1";
        String oid1 = "1.2.3.4";
        String pattern = "";
        Hashtable<String, String> config = new Hashtable<String, String>();
        config.put("oid", oid1);
        config.put("name", name1);
        config.put("pattern", pattern);
        config.put("critical", "true");

        GenericASN1Extension extension1 = new GenericASN1Extension(config);
        Assert.assertEquals(name1, extension1.getName());
        //Assert.assertNotNull(OIDMap.getClass(name1));

        String name2 = "testExtension2";
        String oid2 = "2.4.6.8";
        config.put("oid", oid2);
        config.put("name", name2);

        GenericASN1Extension extension2 = new GenericASN1Extension(config);
        Assert.assertEquals(name2, extension2.getName());
        //Assert.assertNotNull(OIDMap.getClass(name2));
        OutputStream outputStream = new ByteArrayOutputStream();
        extension1.encode(outputStream);
        extension2.encode(outputStream);

    }

    @Test
    public void testConstructorDER() throws Exception {
        byte[] value = new byte[0];
        GenericASN1Extension extension = new GenericASN1Extension(true, value);

        OutputStream outputStream = new ByteArrayOutputStream();
        extension.encode(outputStream);

    }
}
