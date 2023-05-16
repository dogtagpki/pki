package com.netscape.cmscore.request;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Hashtable;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class ExtDataHashtableTest {

    ExtDataHashtable<String> hash;

    @BeforeEach
    public void cmsTestSetUp() {
        hash = new ExtDataHashtable<>();
    }

    @Test
    public void testContainsKey() {
        hash.put("FOO", "bar");
        assertTrue(hash.containsKey("foo"));
        assertTrue(hash.containsKey("Foo"));
    }

    @Test
    public void testGet() {
        hash.put("FOO", "bar");
        assertEquals("bar", hash.get("foo"));
        assertEquals("bar", hash.get("fOO"));
    }

    @Test
    public void testPut() {
        hash.put("FOO", "bar");
        hash.put("foo", "bar2");
        assertEquals(1, hash.keySet().size());
        assertEquals("bar2", hash.get("foo"));
    }

    @Test
    public void testPutAll() {
        Hashtable<String, String> hash2 = new Hashtable<>();
        hash2.put("KEY1", "VAL1");
        hash2.put("KEY2", "val2");

        hash.putAll(hash2);

        assertTrue(hash.containsKey("key1"));
        assertEquals("VAL1", hash.get("key1"));
        assertEquals("val2", hash.get("Key2"));
    }

    @Test
    public void testRemove() {
        hash.put("foo", "bar");
        hash.put("one", "two");

        hash.remove("FOO");
        assertFalse(hash.containsKey("foo"));
        assertTrue(hash.containsKey("one"));
    }

    @Test
    public void testMapConstructor() {
        Hashtable<String, String> hash2 = new Hashtable<>();
        hash2.put("KEY1", "VAL1");
        hash2.put("KEY2", "val2");

        hash = new ExtDataHashtable<>(hash2);

        assertTrue(hash.containsKey("key1"));
        assertEquals("VAL1", hash.get("key1"));
        assertEquals("val2", hash.get("Key2"));
    }

}
