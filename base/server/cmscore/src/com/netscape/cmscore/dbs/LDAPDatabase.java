package com.netscape.cmscore.dbs;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.IDBAttrMapper;
import com.netscape.certsrv.dbs.IDBObj;
import com.netscape.certsrv.dbs.IDBRegistry;
import com.netscape.certsrv.dbs.IDBSSession;
import com.netscape.certsrv.dbs.IDBSearchResults;
import com.netscape.certsrv.dbs.IDBSubsystem;
import com.netscape.certsrv.dbs.Modification;
import com.netscape.certsrv.dbs.ModificationSet;

/**
 * This class implements LDAP database.
 *
 * @author Endi S. Dewata
 */
public abstract class LDAPDatabase<E extends IDBObj> extends Database<E> {

    public IDBSubsystem dbSubsystem;
    public String baseDN;
    public Class<E> recordType;

    public LDAPDatabase(String name, IDBSubsystem dbSubsystem, String baseDN, Class<E> recordType) throws EBaseException {
        super(name);

        this.dbSubsystem = dbSubsystem;
        this.baseDN = baseDN;
        this.recordType = recordType;

        register(recordType);
    }

    public IDBAttrMapper createMapper(Class<?> attrType, DBAttribute dbAttribute) throws EBaseException {
        String attrName = dbAttribute.value();

        if (attrType == String.class) {
            return new StringMapper(attrName);

        } else if (attrType == Date.class) {
            return new DateMapper(attrName);

        } else {
            // TODO: add other mappers
            throw new EBaseException("Unsupported attribute type: " + attrType);
        }
    }

    public void register(Class<E> recordType) throws EBaseException {
        IDBRegistry dbRegistry = dbSubsystem.getRegistry();

        // register object classes
        DBObjectClasses dbObjectClasses = recordType.getAnnotation(DBObjectClasses.class);
        if (dbObjectClasses == null) {
            throw new EBaseException("Missing object class mapping in " + recordType.getName());
        }
        dbRegistry.registerObjectClass(recordType.getName(), dbObjectClasses.value());

        // register attributes defined in setters/getters
        for (Method method : recordType.getMethods()) {
            DBAttribute dbAttribute = method.getAnnotation(DBAttribute.class);
            if (dbAttribute == null) continue;

            String name = method.getName();
            if (!name.matches("^set.+") && !name.matches("^get.+")) continue;

            // get attribute name from method name
            name = Character.toLowerCase(name.charAt(3)) + name.substring(4);

            Class<?> attrType = method.getReturnType();
            IDBAttrMapper mapper = createMapper(attrType, dbAttribute);

            dbRegistry.registerAttribute(name, mapper);
        }

        // register attributes defined in fields
        for (Field field : recordType.getFields()) {
            DBAttribute dbAttribute = field.getAnnotation(DBAttribute.class);
            if (dbAttribute == null) continue;

            String name = field.getName();
            Class<?> attrType = field.getType();
            IDBAttrMapper mapper = createMapper(attrType, dbAttribute);

            dbRegistry.registerAttribute(name, mapper);
        }
    }

    public abstract String createDN(String id);
    public abstract String createFilter(String filter);

    @Override
    public Collection<E> getRecords() throws Exception {
        CMS.debug("LDAPDatabase: getRecords()");

        try (IDBSSession session = dbSubsystem.createSession()) {
            Collection<E> list = new ArrayList<E>();

            CMS.debug("LDAPDatabase: searching " + baseDN);
            IDBSearchResults results = session.search(baseDN, createFilter(null));

            while (results.hasMoreElements()) {
                @SuppressWarnings("unchecked")
                E result = (E)results.nextElement();
                list.add(result);
            }

            return list;
        }
    }

    @SuppressWarnings("unchecked")
    @Override
    public E getRecord(String id) throws Exception {
        CMS.debug("LDAPDatabase: getRecord(\"" + id + "\")");
        try (IDBSSession session = dbSubsystem.createSession()) {
            String dn = createDN(id);
            CMS.debug("LDAPDatabase: reading " + baseDN);
            return (E)session.read(dn);
        }
    }

    @Override
    public void addRecord(String id, E record) throws Exception {
        CMS.debug("LDAPDatabase: addRecord(\"" + id + "\")");
        try (IDBSSession session = dbSubsystem.createSession()) {
            String dn = createDN(id);

            CMS.debug("LDAPDatabase: adding " + dn);
            session.add(dn, record);
        }
    }

    @Override
    public void updateRecord(String id, E record) throws Exception {
        CMS.debug("LDAPDatabase: updateRecord(\"" + id + "\")");
        try (IDBSSession session = dbSubsystem.createSession()) {
            String dn = createDN(id);

            ModificationSet mods = new ModificationSet();
            for (Enumeration<String> names = record.getSerializableAttrNames(); names.hasMoreElements(); ) {
                String name = names.nextElement();
                Object value = record.get(name);
                mods.add(name, Modification.MOD_REPLACE, value);
            }

            CMS.debug("LDAPDatabase: modifying " + dn);
            session.modify(dn, mods);
        }
    }

    @Override
    public void removeRecord(String id) throws Exception {
        CMS.debug("LDAPDatabase: removeRecord(\"" + id + "\")");
        try (IDBSSession session = dbSubsystem.createSession()) {
            String dn = createDN(id);

            CMS.debug("LDAPDatabase: removing " + dn);
            session.delete(dn);
        }
    }

}
