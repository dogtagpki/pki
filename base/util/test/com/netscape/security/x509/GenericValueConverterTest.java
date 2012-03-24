package com.netscape.security.x509;

import org.junit.Test;
import org.junit.Assert;

import com.netscape.security.util.JSSUtil;
import com.netscape.security.util.StringTestUtil;

import netscape.security.util.DerValue;
import netscape.security.x509.GenericValueConverter;

public class GenericValueConverterTest {

    @Test
    public void testEmptyString() throws Exception {

        String string = "";
        System.out.println("Converting: [" + string + "]");

        byte[] expected = JSSUtil.encode(DerValue.tag_PrintableString, string);
        System.out.println(" - expected: " + StringTestUtil.toString(expected));

        byte[] actual = ConverterTestUtil.convert(new GenericValueConverter(), string);
        System.out.println(" - actual  : " + StringTestUtil.toString(actual));

        Assert.assertArrayEquals(expected, actual);
    }

    @Test
    public void testNullCharacters() throws Exception {

        String string = StringTestUtil.NULL_CHARS;
        System.out.println("Converting: [" + StringTestUtil.toString(string.getBytes()) + "]");

        byte[] expected = JSSUtil.encode(DerValue.tag_IA5String, string);
        System.out.println(" - expected: " + StringTestUtil.toString(expected));

        byte[] actual = ConverterTestUtil.convert(new GenericValueConverter(), string);
        System.out.println(" - actual  : " + StringTestUtil.toString(actual));

        Assert.assertArrayEquals(expected, actual);
    }

    @Test
    public void testPrintableCharacters() throws Exception {

        String string = StringTestUtil.PRINTABLE_CHARS;
        System.out.println("Converting: [" + string + "]");

        byte[] expected = JSSUtil.encode(DerValue.tag_PrintableString, string);
        System.out.println(" - expected: " + StringTestUtil.toString(expected));

        byte[] actual = ConverterTestUtil.convert(new GenericValueConverter(), string);
        System.out.println(" - actual  : " + StringTestUtil.toString(actual));

        Assert.assertArrayEquals(expected, actual);
    }

    @Test
    public void testControlCharacters() throws Exception {

        String string = StringTestUtil.CONTROL_CHARS;
        System.out.println("Converting: [" + StringTestUtil.toString(string.getBytes()) + "]");

        byte[] expected = JSSUtil.encode(DerValue.tag_IA5String, string);
        System.out.println(" - expected: " + StringTestUtil.toString(expected));

        byte[] actual = ConverterTestUtil.convert(new GenericValueConverter(), string);
        System.out.println(" - actual  : " + StringTestUtil.toString(actual));

        Assert.assertArrayEquals(expected, actual);
    }

    @Test
    public void testMultibyteCharacters() throws Exception {

        String string = StringTestUtil.MULTIBYTE_CHARS;
        System.out.println("Converting: [" + string + "]");

        byte[] expected = JSSUtil.encode(DerValue.tag_BMPString, string);
        System.out.println(" - expected: " + StringTestUtil.toString(expected));

        byte[] actual = ConverterTestUtil.convert(new GenericValueConverter(), string);
        System.out.println(" - actual  : " + StringTestUtil.toString(actual));

        actual = StringTestUtil.normalizeUnicode(actual);
        System.out.println(" - norm.   : " + StringTestUtil.toString(actual));

        Assert.assertArrayEquals(expected, actual);
    }

    @Test
    public void testPrintableCharactersWithTags() throws Exception {

        String string = StringTestUtil.PRINTABLE_CHARS;
        System.out.println("Converting: [" + string + "]");

        byte[] expected = JSSUtil.encode(DerValue.tag_T61String, string);
        System.out.println(" - expected: " + StringTestUtil.toString(expected));

        byte[] actual = ConverterTestUtil.convert(new GenericValueConverter(), string, new byte[] {
                DerValue.tag_T61String, DerValue.tag_UniversalString
        });
        System.out.println(" - actual  : " + StringTestUtil.toString(actual));

        Assert.assertArrayEquals(expected, actual);
    }

    @Test
    public void testMultibyteCharactersWithTags() throws Exception {

        String string = StringTestUtil.MULTIBYTE_CHARS;
        System.out.println("Converting: [" + string + "]");

        byte[] expected = JSSUtil.encode(DerValue.tag_UniversalString, string);
        System.out.println(" - expected: " + StringTestUtil.toString(expected));

        byte[] actual = ConverterTestUtil.convert(new GenericValueConverter(), string, new byte[] {
                DerValue.tag_T61String, DerValue.tag_UniversalString
        });
        System.out.println(" - actual  : " + StringTestUtil.toString(actual));

        Assert.assertArrayEquals(expected, actual);
    }
}
