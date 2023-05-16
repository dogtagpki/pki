package com.netscape.cmscore.request;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Hashtable;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmscore.dbs.RequestRecordDefaultStub;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;

public class ExtAttrDynMapperTest {

    static ExtAttrDynMapper mapper;

    @BeforeAll
    public static void cmsTestSetUp() {
        mapper = new ExtAttrDynMapper();
    }

    @Test
    public void testSupportLDAPAttributeName() {
        assertNotNull(mapper);

        assertTrue(mapper.supportsLDAPAttributeName("extData-green"));
        assertTrue(mapper.supportsLDAPAttributeName("EXTDATA-green"));
        assertTrue(mapper.supportsLDAPAttributeName("extData-foo;0"));
        assertTrue(mapper.supportsLDAPAttributeName("extData-bar;baz"));

        assertFalse(mapper.supportsLDAPAttributeName("extDatagreen"));
        assertFalse(mapper.supportsLDAPAttributeName("extDatafoo;0"));
        assertFalse(mapper.supportsLDAPAttributeName("extDatabar;baz"));

        assertFalse(mapper.supportsLDAPAttributeName(";extData"));
        assertFalse(mapper.supportsLDAPAttributeName("fooextData"));
        assertFalse(mapper.supportsLDAPAttributeName("foo-extData"));

        assertFalse(mapper.supportsLDAPAttributeName(""));
        assertFalse(mapper.supportsLDAPAttributeName(null));
    }

    @Test
    public void testGetSupportedLdapAttributesNames() {
        Enumeration<String> attrs = mapper.getSupportedLDAPAttributeNames();
        ArrayList<String> attrsList = new ArrayList<>();
        while (attrs.hasMoreElements()) {
            attrsList.add(attrs.nextElement());
        }

        assertEquals(1, attrsList.size());
        assertEquals(Schema.LDAP_ATTR_EXT_ATTR, attrsList.get(0));
    }

    @Test
    public void testIsAlphaNum() {
        assertTrue(mapper.isAlphaNum('a'));
        assertTrue(mapper.isAlphaNum('l'));
        assertTrue(mapper.isAlphaNum('z'));
        assertTrue(mapper.isAlphaNum('A'));
        assertTrue(mapper.isAlphaNum('K'));
        assertTrue(mapper.isAlphaNum('Z'));
        assertTrue(mapper.isAlphaNum('0'));
        assertTrue(mapper.isAlphaNum('5'));
        assertTrue(mapper.isAlphaNum('9'));

        assertFalse(mapper.isAlphaNum('!'));
        assertFalse(mapper.isAlphaNum('-'));
        assertFalse(mapper.isAlphaNum('\u00ef'));
    }

    @Test
    public void testEncodeDecodeKey() {
        // ; is 003b
        // $ is 0024
        // % is 0025
        // - is 002d

        String decoded = ";a$c%d-";
        String encoded = "--003ba--0024c--0025d-";
        assertEquals(encoded, mapper.encodeKey(decoded));
        assertEquals(decoded, mapper.decodeKey(encoded));

        decoded = ";-a-";
        encoded = "--003b--002da-";
        assertEquals(encoded, mapper.encodeKey(decoded));
        assertEquals(decoded, mapper.decodeKey(encoded));

        decoded = "-ab;ab";
        encoded = "-ab--003bab";
        assertEquals(encoded, mapper.encodeKey(decoded));
        assertEquals(decoded, mapper.decodeKey(encoded));

        decoded = "--a--b-a-b-";
        encoded = "--002d--002da--002d--002db-a-b-";
        assertEquals(encoded, mapper.encodeKey(decoded));
        assertEquals(decoded, mapper.decodeKey(encoded));

        decoded = "--a;-";
        encoded = "--002d--002da--003b--002d";
        assertEquals(encoded, mapper.encodeKey(decoded));
        assertEquals(decoded, mapper.decodeKey(encoded));
    }

    @Test
    public void testMapObjectToLDAPAttributeSet() throws EBaseException {
        LDAPAttributeSet attrs = new LDAPAttributeSet();

        // test with a key-value entry.
        Hashtable<String, Serializable> extAttrsHash = new Hashtable<>();
        extAttrsHash.put("foo;", "bar");

        mapper.mapObjectToLDAPAttributeSet(null, null, extAttrsHash, attrs);
        assertEquals(1, attrs.size());
        assertEquals(ExtAttrDynMapper.extAttrPrefix + "foo--003b",
                attrs.elementAt(0).getName());
        String vals[] = attrs.elementAt(0).getStringValueArray();
        assertEquals(1, vals.length);
        assertEquals("bar", vals[0]);

        // test with a sub-hash.
        // this is used by vector/arrays and hashtables
        Hashtable<String, String> extAttrsValueHash = new Hashtable<>();
        extAttrsValueHash.put("Baz", "Val1");
        extAttrsValueHash.put("bi;m", "val2");

        extAttrsHash.clear();
        extAttrsHash.put("top;key", extAttrsValueHash);

        attrs = new LDAPAttributeSet();
        mapper.mapObjectToLDAPAttributeSet(null, null, extAttrsHash, attrs);
        assertEquals(2, attrs.size());
        LDAPAttribute attrBaz = attrs.elementAt(0);
        LDAPAttribute attrBim = attrs.elementAt(1);
        // swap attributes if necessary
        if (attrBaz.getName().equals(ExtAttrDynMapper.extAttrPrefix +
                "top--003bkey;bi--003bm")) {
            attrBaz = attrs.elementAt(1);
            attrBim = attrs.elementAt(0);
        }

        assertEquals(ExtAttrDynMapper.extAttrPrefix + "top--003bkey;Baz",
                attrBaz.getName());
        vals = attrBaz.getStringValueArray();
        assertEquals(1, vals.length);
        assertEquals("Val1", vals[0]);
        assertTrue(attrBaz.hasSubtype("Baz"));

        assertEquals(ExtAttrDynMapper.extAttrPrefix + "top--003bkey;bi--003bm",
                attrBim.getName());
        vals = attrBim.getStringValueArray();
        assertEquals(1, vals.length);
        assertEquals("val2", vals[0]);
        assertTrue(attrBim.hasSubtype("bi--003bm"));
    }

    @Test
    public void testMapLDAPAttributeSetToObject() throws EBaseException {
        //
        // Test simple key-value pairs
        //
        LDAPAttributeSet attrs = new LDAPAttributeSet();
        attrs.add(new LDAPAttribute(
                ExtAttrDynMapper.extAttrPrefix + "o--003bkey1", "val1"));
        attrs.add(new LDAPAttribute("junk", "junkval"));
        attrs.add(new LDAPAttribute(
                ExtAttrDynMapper.extAttrPrefix + "okey2", "val2"));

        RequestRecordStub requestRecord = new RequestRecordStub();

        mapper.mapLDAPAttributeSetToObject(attrs, RequestRecord.ATTR_EXT_DATA, requestRecord);

        assertEquals(1, requestRecord.setCallCounter);
        Hashtable<?, ?> extData = (Hashtable<?, ?>) requestRecord.extAttrData.get(RequestRecord.ATTR_EXT_DATA);
        assertNotNull(extData);

        assertEquals(2, extData.keySet().size());
        assertTrue(extData.containsKey("o;key1"));
        assertEquals("val1", extData.get("o;key1"));
        assertTrue(extData.containsKey("okey2"));
        assertEquals("val2", extData.get("okey2"));

        //
        // Test subkeys
        //
        attrs = new LDAPAttributeSet();
        attrs.add(new LDAPAttribute(
                ExtAttrDynMapper.extAttrPrefix + "o--003bkey1;i--003bkey11", "val11"));
        attrs.add(new LDAPAttribute(
                ExtAttrDynMapper.extAttrPrefix.toUpperCase() + "o--003bkey1;ikey12", "val12"));
        attrs.add(new LDAPAttribute(
                ExtAttrDynMapper.extAttrPrefix + "o--003bkey1;ikey13", "val13"));
        attrs.add(new LDAPAttribute(
                ExtAttrDynMapper.extAttrPrefix + "okey2;ikey21", "val21"));
        attrs.add(new LDAPAttribute(
                ExtAttrDynMapper.extAttrPrefix + "okey2;ikey22", "val22"));
        attrs.add(new LDAPAttribute("foo", "bar"));

        requestRecord = new RequestRecordStub();

        mapper.mapLDAPAttributeSetToObject(attrs, RequestRecord.ATTR_EXT_DATA, requestRecord);

        assertEquals(1, requestRecord.setCallCounter);
        extData = (Hashtable<?, ?>) requestRecord.extAttrData.get(RequestRecord.ATTR_EXT_DATA);
        assertNotNull(extData);

        assertTrue(extData.containsKey("o;key1"));
        Hashtable<?, ?> okey1Data = (Hashtable<?, ?>) extData.get("o;key1");
        assertEquals(3, okey1Data.keySet().size());
        assertTrue(okey1Data.containsKey("i;key11"));
        assertEquals("val11", okey1Data.get("i;key11"));
        assertTrue(okey1Data.containsKey("ikey12"));
        assertEquals("val12", okey1Data.get("ikey12"));
        assertTrue(okey1Data.containsKey("ikey13"));
        assertEquals("val13", okey1Data.get("ikey13"));

        assertTrue(extData.containsKey("okey2"));
        Hashtable<?, ?> okey2Data = (Hashtable<?, ?>) extData.get("okey2");
        assertEquals(2, okey2Data.keySet().size());
        assertTrue(okey2Data.containsKey("ikey21"));
        assertEquals("val21", okey2Data.get("ikey21"));
        assertTrue(okey2Data.containsKey("ikey22"));
        assertEquals("val22", okey2Data.get("ikey22"));

        assertFalse(extData.containsKey("foo"));

        //
        // test illegal data combination
        //
        LDAPAttributeSet attrsSet = new LDAPAttributeSet();
        attrsSet.add(new LDAPAttribute(
                ExtAttrDynMapper.extAttrPrefix + "okey1", "val11"));
        attrsSet.add(new LDAPAttribute(
                ExtAttrDynMapper.extAttrPrefix + "okey1;ikey12", "val12"));

        assertThrows(EBaseException.class, () ->
            mapper.mapLDAPAttributeSetToObject(attrsSet, RequestRecord.ATTR_EXT_DATA, new RequestRecordStub())
        );
    }

    static class RequestRecordStub extends RequestRecordDefaultStub {

        Hashtable<String, Object> extAttrData = new Hashtable<>();
        int setCallCounter = 0;

        @Override
        public void set(String name, Object o) {
            setCallCounter++;
            if (RequestRecord.ATTR_EXT_DATA.equals(name)) {
                extAttrData.put(name, o);
            }
        }

        @Override
        public RequestId getRequestId() {
            return new RequestId("1");
        }
    }
}
