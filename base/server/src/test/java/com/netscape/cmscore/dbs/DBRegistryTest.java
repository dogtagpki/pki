package com.netscape.cmscore.dbs;

import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.MissingResourceException;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.EDBException;
import com.netscape.certsrv.dbs.IDBObj;
import com.netscape.cmscore.request.DBDynAttrMapper;
import com.netscape.cmscore.request.RequestRecord;
import com.netscape.cmscore.test.CMSBaseTestCase;
import com.netscape.cmscore.test.TestHelper;

import junit.framework.Test;
import junit.framework.TestSuite;
import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;

public class DBRegistryTest extends CMSBaseTestCase {

    DBSubsystemStub db;
    DBRegistry registry;
    DBDynAttrMapperStub extAttrMapper;
    RequestRecordStub requestRecordStub = new RequestRecordStub();

    public DBRegistryTest(String name) {
        super(name);
    }

    @Override
    public void cmsTestSetUp() {
        db = new DBSubsystemStub();
        registry = new LDAPRegistry();
        db.registry = registry;

        // Emulate the registration of mappers.
        // Normally RequestRepository calls RequestRecord.register() as part
        // of a long chain of initialization calls.
        extAttrMapper = new DBDynAttrMapperStub();
        try {
            registry.registerObjectClass(requestRecordStub.getClass().getName(),
                    new String[] { "ocvalue" });
            registry.registerAttribute(RequestRecord.ATTR_EXT_DATA, extAttrMapper);
            registry.registerAttribute(RequestRecord.ATTR_SOURCE_ID,
                    new StringMapper("sourceIdOut"));
            registry.registerDynamicMapper(extAttrMapper);
        } catch (EDBException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void cmsTestTearDown() {
    }

    public static Test suite() {
        return new TestSuite(DBRegistryTest.class);
    }

    public void testMapObject() throws EBaseException {
        assertFalse(extAttrMapper.mapObjectCalled);
        registry.mapObject(null, RequestRecord.ATTR_EXT_DATA, null, new LDAPAttributeSet());
        assertTrue(extAttrMapper.mapObjectCalled);
    }

    public void testGetLDAPAttributesForExtData() throws EBaseException {
        String inAttrs[] = new String[] {
                "extData-foo",
                "extData-foo12",
                "EXTDATA-bar;baz",
                RequestRecord.ATTR_SOURCE_ID
        };
        String outAttrs[] = registry.getLDAPAttributes(inAttrs);

        assertTrue(TestHelper.contains(outAttrs, inAttrs[0]));
        assertTrue(TestHelper.contains(outAttrs, inAttrs[1]));
        assertTrue(TestHelper.contains(outAttrs, inAttrs[2]));
        assertTrue(TestHelper.contains(outAttrs, "sourceIdOut"));

        try {
            registry.getLDAPAttributes(new String[] { "badattr" });
            fail("Should not be able to map badattr");
        } catch (EBaseException | MissingResourceException e) { /* good */
        }
    }

    public void testCreateLDAPAttributeSet() throws EBaseException {
        assertFalse(extAttrMapper.mapObjectCalled);

        registry.createLDAPAttributeSet(requestRecordStub);
        assertTrue(requestRecordStub.getCalled);
        assertEquals(requestRecordStub.getCalledWith,
                RequestRecord.ATTR_EXT_DATA);

        // This asserts that mapObject() is called and makes it down to the
        // extDataDynAttrMapper.mapObjectToLDAPAttributeSet() call.
        assertTrue(extAttrMapper.mapObjectCalled);
    }

    public void testCreateObject() throws EBaseException {
        LDAPAttributeSet attrs = new LDAPAttributeSet();
        attrs.add(new LDAPAttribute("objectclass", "ocvalue"));
        attrs.add(new LDAPAttribute("extdata-foo"));

        assertFalse(extAttrMapper.mapLDAPAttrsCalled);

        registry.createObject(attrs);

        assertTrue(extAttrMapper.mapLDAPAttrsCalled);
    }

    static class DBSubsystemStub extends DBSubsystem {
        DBRegistry registry;

        @Override
        public DBRegistry getRegistry() {
            return registry;
        }
    }

    static class DBDynAttrMapperStub extends DBDynAttrMapper {
        boolean mapObjectCalled = false;
        Object mapObjectCalledWithObject = null;
        boolean mapLDAPAttrsCalled = false;

        @Override
        public boolean supportsLDAPAttributeName(String attrName) {
            return (attrName != null) &&
                    attrName.toLowerCase().startsWith("extdata-");
        }

        @Override
        public void mapLDAPAttributeSetToObject(LDAPAttributeSet attrs, String name, IDBObj parent)
                throws EBaseException {
            mapLDAPAttrsCalled = true;
        }

        @Override
        public void mapObjectToLDAPAttributeSet(IDBObj parent, String name,
                                                Object obj,
                                                LDAPAttributeSet attrs)
                throws EBaseException {
            mapObjectCalled = true;
            mapObjectCalledWithObject = obj;
        }
    }

}

/*
 * This class is purposefully placed outside the test because
 * DBRegistry.createObject() calls Class.newInstance() to create
 * this stub.  This fails if the class is nested.
 */
class RequestRecordStub extends RequestRecordDefaultStub {

    /**
     *
     */
    private static final long serialVersionUID = 2155124580267335995L;

    String[] attrs = new String[] { RequestRecord.ATTR_EXT_DATA };

    boolean getCalled = false;
    String getCalledWith = null;
    boolean getSerializedAttrNamesCalled = false;

    @Override
    public Object get(String name) {
        getCalled = true;
        getCalledWith = name;
        return "foo";
    }

    @Override
    public Enumeration<String> getSerializableAttrNames() {
        getSerializedAttrNamesCalled = true;
        return Collections.enumeration(Arrays.asList(attrs));
    }
}
