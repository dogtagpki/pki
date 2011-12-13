package com.netscape.security.util;

import java.io.IOException;

import org.junit.Test;
import org.junit.Assert;

import sun.security.util.DerValue;

public class TeletexStringTest {

    public byte tag = DerValue.tag_T61String;

    @Test
    public void testEncodingEmptyString() throws Exception {

        String string = "";
        System.out.println("Encoding: ["+string+"]");

        byte[] expected = JSSUtil.encode(tag, string);
        System.out.println(" - expected: "+StringTestUtil.toString(expected));

        byte[] actual = StringTestUtil.encode(tag, string);
        System.out.println(" - actual  : "+StringTestUtil.toString(actual));

        Assert.assertArrayEquals(expected, actual);
    }

    @Test
    public void testDecodingEmptyString() throws Exception {

        String input = "";
        byte[] data = JSSUtil.encode(tag, input);

        System.out.println("Decoding: ["+StringTestUtil.toString(data)+"]");

        System.out.println(" - expected: ["+input+"]");

        String output = StringTestUtil.decode(tag, data);
        System.out.println(" - actual  : ["+output+"]");

        Assert.assertEquals(input, output);
    }

    @Test
    public void testEncodingPrintableCharacters() throws Exception {

        String string = StringTestUtil.PRINTABLE_CHARS;
        System.out.println("Encoding: ["+string+"]");

        byte[] expected = JSSUtil.encode(tag, string);
        System.out.println(" - expected: "+StringTestUtil.toString(expected));

        byte[] actual = StringTestUtil.encode(tag, string);
        System.out.println(" - actual  : "+StringTestUtil.toString(actual));

        Assert.assertArrayEquals(expected, actual);
    }

    @Test
    public void testDecodingPrintableCharacters() throws Exception {

        String input = StringTestUtil.PRINTABLE_CHARS;
        byte[] data = JSSUtil.encode(tag, input);

        System.out.println("Decoding: ["+StringTestUtil.toString(data)+"]");

        System.out.println(" - expected: ["+input+"]");

        String output = StringTestUtil.decode(tag, data);
        System.out.println(" - actual  : ["+output+"]");

        Assert.assertEquals(input, output);
    }

    @Test
    public void testEncodingNonPrintableCharacters() throws Exception {

        String string = StringTestUtil.NON_PRINTABLE_CHARS;
        System.out.println("Encoding: ["+string+"]");

        byte[] expected = JSSUtil.encode(tag, string);
        System.out.println(" - expected: "+StringTestUtil.toString(expected));

        byte[] actual = StringTestUtil.encode(tag, string);
        System.out.println(" - actual  : "+StringTestUtil.toString(actual));

        Assert.assertArrayEquals(expected, actual);
    }

    @Test
    public void testDecodingNonPrintableCharacters() throws Exception {

        String input = StringTestUtil.NON_PRINTABLE_CHARS;
        byte[] data = JSSUtil.encode(tag, input);

        System.out.println("Decoding: ["+StringTestUtil.toString(data)+"]");

        System.out.println(" - expected: ["+input+"]");

        String output = StringTestUtil.decode(tag, data);
        System.out.println(" - actual  : ["+output+"]");

        Assert.assertEquals(input, output);
    }

    @Test
    public void testEncodingControlCharacters() throws Exception {

        String string = StringTestUtil.CONTROL_CHARS;
        System.out.println("Encoding: ["+StringTestUtil.toString(string.getBytes())+"]");

        byte[] expected = JSSUtil.encode(tag, string);
        System.out.println(" - expected: "+StringTestUtil.toString(expected));

        byte[] actual = StringTestUtil.encode(tag, string);
        System.out.println(" - actual  : "+StringTestUtil.toString(actual));

        Assert.assertArrayEquals(expected, actual);
    }

    @Test
    public void testDecodingControlCharacters() throws Exception {

        String input = StringTestUtil.CONTROL_CHARS;
        byte[] data = JSSUtil.encode(tag, input);

        System.out.println("Decoding: ["+StringTestUtil.toString(data)+"]");

        System.out.println(" - expected: ["+StringTestUtil.toString(input.getBytes())+"]");

        String output = StringTestUtil.decode(tag, data);
        System.out.println(" - actual  : ["+StringTestUtil.toString(output.getBytes())+"]");

        Assert.assertEquals(input, output);
    }

    @Test
    public void testEncodingMultibyteCharacters() throws Exception {

        String string = StringTestUtil.MULTIBYTE_CHARS;
        System.out.println("Encoding: ["+string+"]");

        System.out.println(" - expected: IOException");

        try {
            byte[] actual = StringTestUtil.encode(tag, string);
            System.out.println(" - actual  : "+StringTestUtil.toString(actual));

            Assert.fail();

        } catch (Exception e) {
            System.out.println(" - actual  : "+e.getClass().getSimpleName());
            Assert.assertTrue(e instanceof IOException);
        }
    }

    @Test
    public void testDecodingMultibyteCharacters() throws Exception {

        String input = StringTestUtil.MULTIBYTE_CHARS;
        byte[] data = JSSUtil.encode(DerValue.tag_UTF8String, input);

        System.out.println("Decoding: ["+StringTestUtil.toString(data)+"]");

        System.out.println(" - expected: IOException");

        try {
            String output = StringTestUtil.decode(tag, data);
            System.out.println(" - actual  : ["+StringTestUtil.toString(output.getBytes())+"]");

            Assert.fail();

        } catch (Exception e) {
            System.out.println(" - actual  : "+e.getClass().getSimpleName());
            Assert.assertTrue(e instanceof IOException);
        }
    }
}
