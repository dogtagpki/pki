package com.netscape.security.x509;

import org.junit.Test;
import org.junit.Assert;

import com.netscape.security.util.JSSUtil;
import com.netscape.security.util.StringTestUtil;

import org.mozilla.jss.netscape.security.util.DerValue;
import org.mozilla.jss.netscape.security.x509.IA5StringConverter;

public class IA5StringConverterTest {

    @Test
    public void testEmptyString() throws Exception {

        String string = "";
        System.out.println("Converting: [" + string + "]");

        byte[] expected = JSSUtil.encode(DerValue.tag_IA5String, string);
        System.out.println(" - expected: " + StringTestUtil.toString(expected));

        byte[] actual = ConverterTestUtil.convert(new IA5StringConverter(), string);
        System.out.println(" - actual  : " + StringTestUtil.toString(actual));

        Assert.assertArrayEquals(expected, actual);
    }

    @Test
    public void testNullCharacters() throws Exception {

        String string = StringTestUtil.NULL_CHARS;
        System.out.println("Converting: [" + StringTestUtil.toString(string.getBytes()) + "]");

        byte[] expected = JSSUtil.encode(DerValue.tag_IA5String, string);
        System.out.println(" - expected: " + StringTestUtil.toString(expected));

        byte[] actual = ConverterTestUtil.convert(new IA5StringConverter(), string);
        System.out.println(" - actual  : " + StringTestUtil.toString(actual));

        Assert.assertArrayEquals(expected, actual);
    }

    @Test
    public void testPrintableCharacters() throws Exception {

        String string = StringTestUtil.PRINTABLE_CHARS;
        System.out.println("Converting: [" + string + "]");

        byte[] expected = JSSUtil.encode(DerValue.tag_IA5String, string);
        System.out.println(" - expected: " + StringTestUtil.toString(expected));

        byte[] actual = ConverterTestUtil.convert(new IA5StringConverter(), string);
        System.out.println(" - actual  : " + StringTestUtil.toString(actual));

        Assert.assertArrayEquals(expected, actual);
    }

    @Test
    public void testControlCharacters() throws Exception {

        String string = StringTestUtil.CONTROL_CHARS;
        System.out.println("Converting: [" + StringTestUtil.toString(string.getBytes()) + "]");

        byte[] expected = JSSUtil.encode(DerValue.tag_IA5String, string);
        System.out.println(" - expected: " + StringTestUtil.toString(expected));

        byte[] actual = ConverterTestUtil.convert(new IA5StringConverter(), string);
        System.out.println(" - actual  : " + StringTestUtil.toString(actual));

        Assert.assertArrayEquals(expected, actual);
    }

    @Test
    public void testMultibyteCharacters() throws Exception {

        String string = StringTestUtil.MULTIBYTE_CHARS;
        System.out.println("Converting: [" + string + "]");

        System.out.println(" - expected: IllegalArgumentException");

        try {
            byte[] actual = ConverterTestUtil.convert(new IA5StringConverter(), string);
            System.out.println(" - actual  : " + StringTestUtil.toString(actual));

            Assert.fail();

        } catch (Exception e) {
            System.out.println(" - actual  : " + e.getClass().getSimpleName());
            Assert.assertTrue(e instanceof IllegalArgumentException);
        }
    }
}
