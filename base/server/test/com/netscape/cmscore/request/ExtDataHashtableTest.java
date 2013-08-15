package com.netscape.cmscore.request;

import java.util.Hashtable;

import junit.framework.Test;
import junit.framework.TestSuite;

import com.netscape.cmscore.test.CMSBaseTestCase;

public class ExtDataHashtableTest extends CMSBaseTestCase {

    ExtDataHashtable<String> hash;

    public ExtDataHashtableTest(String name) {
        super(name);
    }

    public void cmsTestSetUp() {
        hash = new ExtDataHashtable<String>();
    }

    public void cmsTestTearDown() {
    }

    public static Test suite() {
        return new TestSuite(ExtDataHashtableTest.class);
    }

    public void testContainsKey() {
        hash.put("FOO", "bar");
        assertTrue(hash.containsKey("foo"));
        assertTrue(hash.containsKey("Foo"));
    }

    public void testGet() {
        hash.put("FOO", "bar");
        assertEquals("bar", hash.get("foo"));
        assertEquals("bar", hash.get("fOO"));
    }

    public void testPut() {
        hash.put("FOO", "bar");
        hash.put("foo", "bar2");
        assertEquals(1, hash.keySet().size());
        assertEquals("bar2", hash.get("foo"));
    }

    public void testPutAll() {
        Hashtable<String, String> hash2 = new Hashtable<String, String>();
        hash2.put("KEY1", "VAL1");
        hash2.put("KEY2", "val2");

        hash.putAll(hash2);

        assertTrue(hash.containsKey("key1"));
        assertEquals("VAL1", hash.get("key1"));
        assertEquals("val2", hash.get("Key2"));
    }

    public void testRemove() {
        hash.put("foo", "bar");
        hash.put("one", "two");

        hash.remove("FOO");
        assertFalse(hash.containsKey("foo"));
        assertTrue(hash.containsKey("one"));
    }

    public void testMapConstructor() {
        Hashtable<String, String> hash2 = new Hashtable<String, String>();
        hash2.put("KEY1", "VAL1");
        hash2.put("KEY2", "val2");

        hash = new ExtDataHashtable<String>(hash2);

        assertTrue(hash.containsKey("key1"));
        assertEquals("VAL1", hash.get("key1"));
        assertEquals("val2", hash.get("Key2"));
    }

}
