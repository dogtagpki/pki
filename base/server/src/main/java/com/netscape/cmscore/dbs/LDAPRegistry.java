// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmscore.dbs;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.Vector;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.DBAttrMapper;
import com.netscape.certsrv.dbs.DBException;
import com.netscape.certsrv.dbs.FilterConverter;
import com.netscape.certsrv.dbs.IDBObj;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.request.DBDynAttrMapper;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;

/**
 * A class represents a registry where all the
 * schema (object classes and attribute) information
 * is stored.
 *
 * Attribute mappers can be registered with this
 * registry.
 *
 * Given the schema information stored, this registry
 * has knowledge to convert a Java object into a
 * LDAPAttributeSet or vice versa.
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class LDAPRegistry extends DBRegistry {

    public final static Logger logger = LoggerFactory.getLogger(LDAPRegistry.class);

    private ConfigStore mConfig = null;
    private Hashtable<String, String[]> mOCclassNames = new Hashtable<>();
    private Hashtable<String, NameAndObject> mOCldapNames = new Hashtable<>();
    private Hashtable<String, DBAttrMapper> mAttrufNames = new Hashtable<>();
    private FilterConverter mConverter;
    private Vector<DBDynAttrMapper> mDynAttrMappers = new Vector<>();

    /**
     * Constructs registry.
     */
    public LDAPRegistry() {
    }

    /**
     * Retrieves subsystem identifier.
     */
    @Override
    public String getId() {
        return "dbsregistry";
    }

    /**
     * Sets subsystem identifier. This is an internal
     * subsystem, and is not loadable.
     */
    @Override
    public void setId(String id) throws EBaseException {
        throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_OPERATION"));
    }

    /**
     * Initializes the internal registery. Connects to the
     * data source, and create a pool of connection of which
     * applications can use. Optionally, check the integrity
     * of the database.
     */
    @Override
    public void init(ConfigStore config)
            throws EBaseException {
        mConfig = config;
        mConverter = new LdapFilterConverter(mAttrufNames);
    }

    /**
     * Retrieves configuration store.
     */
    @Override
    public ConfigStore getConfigStore() {
        return mConfig;
    }

    /**
     * Starts up this subsystem.
     */
    @Override
    public void startup() throws EBaseException {
    }

    /**
     * Shutdowns this subsystem gracefully.
     */
    @Override
    public void shutdown() {
        mOCclassNames.clear();
        mOCldapNames.clear();
        mAttrufNames.clear();
    }

    /**
     * Registers object class.
     */
    @Override
    public void registerObjectClass(String className, String ldapNames[])
            throws DBException {
        try {
            Class<?> c = Class.forName(className);

            mOCclassNames.put(className, ldapNames);
            mOCldapNames.put(sortAndConcate(
                    ldapNames).toLowerCase(),
                    new NameAndObject(className, c));
        } catch (ClassNotFoundException e) {

            /*LogDoc
             *
             * @phase db startup
             * @reason failed to register object class
             * @message LDAPRegistry: <exception thrown>
             */
            logger.error("LDAPRegistry: " + CMS.getUserMessage("CMS_DBS_INVALID_CLASS_NAME", className), e);
            throw new DBException(CMS.getUserMessage("CMS_DBS_INVALID_CLASS_NAME", className), e);
        }
    }

    /**
     * See if an object class is registered.
     */
    @Override
    public boolean isObjectClassRegistered(String className) {
        return mOCclassNames.containsKey(className);
    }

    /**
     * Registers attribute mapper.
     */
    @Override
    public void registerAttribute(String ufName, DBAttrMapper mapper)
            throws DBException {
        // should not allows 'objectclass' as attribute; it has
        // special meaning
        mAttrufNames.put(ufName.toLowerCase(), mapper);
    }

    /**
     * See if an attribute is registered.
     */
    @Override
    public boolean isAttributeRegistered(String ufName) {
        return mAttrufNames.containsKey(ufName.toLowerCase());
    }

    @Override
    public void registerDynamicMapper(DBDynAttrMapper mapper) {
        mDynAttrMappers.add(mapper);
    }

    /**
     * Creates LDAP-based search filters with help of
     * registered mappers.
     * Parses filter from filter string specified in RFC1558.
     *
     * <pre>{@Code
     * <filter> ::= '(' <filtercomp> ')'
     * <filtercomp> ::= <and> | <or> | <not> | <item>
     * <and> ::= '&' <filterlist>
     * <or> ::= '|' <filterlist>
     * <not> ::= '!' <filter>
     * <filterlist> ::= <filter> | <filter> <filterlist>
     * <item> ::= <simple> | <present> | <substring>
     * <simple> ::= <attr> <filtertype> <value>
     * <filtertype> ::= <equal> | <approx> | <greater> | <less>
     * <equal> ::= '='
     * <approx> ::= '~='
     * <greater> ::= '>='
     * <less> ::= '<='
     * <present> ::= <attr> '=*'
     * <substring> ::= <attr> '=' <initial> <any> <final>
     * <initial> ::= NULL | <value>
     * <any> ::= '*' <starval>
     * <starval> ::= NULL | <value> '*' <starval>
     * <final> ::= NULL | <value>
     * }</pre>
     */
    @Override
    public String getFilter(String filter) throws EBaseException {
        return getFilter(filter, mConverter);
    }

    @Override
    public String getFilter(String filter, FilterConverter c)
            throws EBaseException {
        String f = filter;

        f = f.trim();
        if (f.startsWith("(") && f.endsWith(")")) {
            return "(" + getFilterComp(f.substring(1,
                        f.length() - 1), c) + ")";
        }
        return getFilterComp(filter, c);
    }

    private String getFilterComp(String f, FilterConverter c)
            throws EBaseException {
        f = f.trim();
        if (f.startsWith("&")) { // AND operation
            return "&" + getFilterList(f.substring(1,
                        f.length()), c);
        } else if (f.startsWith("|")) { // OR operation
            return "|" + getFilterList(f.substring(1,
                        f.length()), c);
        } else if (f.startsWith("!")) { // NOT operation
            return "!" + getFilter(f.substring(1, f.length()), c);
        } else { // item
            return getFilterItem(f, c);
        }
    }

    private String getFilterList(String f, FilterConverter c)
            throws EBaseException {
        f = f.trim();
        int level = 0;
        int start = 0;
        int end = 0;
        Vector<String> v = new Vector<>();

        for (int i = 0; i < f.length(); i++) {
            if (f.charAt(i) == '(') {
                if (level == 0) {
                    start = i;
                }
                level++;
            }
            if (f.charAt(i) == ')') {
                level--;
                if (level == 0) {
                    end = i;
                    String filter = getFilter(f.substring(start, end + 1), c);

                    v.addElement(filter);
                }
            }
        }
       return inStringFormat(v);
    }

    /**
     * Convert a Vector<String> to Concatenated String
     * @param v
     * @return
     */
    private String inStringFormat(Vector<String> v){
        StringBuffer result = new StringBuffer();

        for (int i = 0; i < v.size(); i++) {
            result.append(v.elementAt(i));
        }
        return result.toString();
    }

    /**
     * So, here we need to separate item into name, op, value.
     */
    private String getFilterItem(String f, FilterConverter c)
            throws EBaseException {
        f = f.trim();
        int idx = f.indexOf('=');

        if (idx == -1) {
            throw new DBException(
                    CMS.getUserMessage("CMS_DBS_INVALID_FILTER_ITEM", "="));
        }

        String type = f.substring(0, idx).trim();
        String value = f.substring(idx + 1).trim(); // skip '='

        // make decision by looking at the type
        type = type.trim();
        if (type.endsWith("~")) {
            // approximate match
            String name = type.substring(0, type.length() - 1).trim();

            return c.convert(name, "~=", value);
        } else if (type.endsWith("!")) {
            String name = type.substring(0, type.length() - 1).trim();

            return c.convert(name, "!=", value);
        } else if (type.endsWith(">")) {
            // greater than
            String name = type.substring(0, type.length() - 1).trim();

            return c.convert(name, ">=", value);
        } else if (type.endsWith("<")) {
            String name = type.substring(0, type.length() - 1).trim();

            return c.convert(name, "<=", value);
        }

        // for those that are not simple
        if (value.startsWith("*") && value.length() == 1) {
            return c.convert(type, "=", "*");
        }

        // if value contains no '*', then it is equality
        if (value.indexOf('*') == -1) {
            if (type.equalsIgnoreCase("objectclass")) {
                String ldapNames[] = mOCclassNames.get(value);

                if (ldapNames == null)
                    throw new DBException(
                            CMS.getUserMessage("CMS_DBS_INVALID_FILTER_ITEM", f));
                StringBuffer filter = new StringBuffer();

                for (int g = 0; g < ldapNames.length; g++) {
                    filter.append("(objectclass=" +
                            ldapNames[g] + ")");
                }
                return "&" + filter.toString();
            }
            return c.convert(type, "=", value);
        }
        // XXX - does not support substring!!
        return c.convert(type, "=", value);
    }

    /**
     * Maps object into LDAP attribute set.
     */
    @Override
    public void mapObject(IDBObj parent, String name, Object obj,
            LDAPAttributeSet attrs) throws EBaseException {
        DBAttrMapper mapper = mAttrufNames.get(name.toLowerCase());

        if (mapper == null) {
            return; // no mapper found, just skip this attribute
        }
        mapper.mapObjectToLDAPAttributeSet(parent, name, obj, attrs);
    }

    /**
     * Retrieves a list of LDAP attributes that are associated
     * with the given attributes.
     * This method is used for searches, to map the database attributes
     * to LDAP attributes.
     */
    @Override
    public String[] getLDAPAttributes(String attrs[])
            throws EBaseException {

        if (attrs == null)
            return null;

        // ignore duplicates, maintain order
        Set<String> v = new LinkedHashSet<>();

        logger.debug("LDAPRegistry: mapping attributes:");

        for (int i = 0; i < attrs.length; i++) {

            String attr = attrs[i];
            logger.debug("LDAPRegistry: - " + attr);

            String prefix = "";

            // check reverse sort order
            if (attr.startsWith("-")) {
                attr = attr.substring(1);
                prefix = "-";
            }

            if (attr.equalsIgnoreCase("objectclass")) {
                v.add(prefix + attr);
                continue;
            }

            if (isAttributeRegistered(attr)) {

                logger.debug("LDAPRegistry:   attribute is registered");

                DBAttrMapper mapper = mAttrufNames.get(attr.toLowerCase());
                if (mapper == null) {
                    throw new DBException(CMS.getUserMessage("CMS_DBS_INVALID_ATTRS"));
                }
                Enumeration<String> e = mapper.getSupportedLDAPAttributeNames();

                while (e.hasMoreElements()) {
                    String s = e.nextElement();
                    v.add(prefix + s);
                }

            } else {

                logger.debug("LDAPRegistry:   checking dynamic mapper");

                DBDynAttrMapper matchingDynAttrMapper = null;
                for (Iterator<DBDynAttrMapper> dynMapperIter = mDynAttrMappers.iterator(); dynMapperIter.hasNext();) {
                    DBDynAttrMapper dynAttrMapper = dynMapperIter.next();
                    if (dynAttrMapper.supportsLDAPAttributeName(attr)) {
                        logger.debug("LDAPRegistry:   found dynamic mapper: " + dynAttrMapper);
                        matchingDynAttrMapper = dynAttrMapper;
                        break;
                    }
                }

                if (matchingDynAttrMapper != null) {
                    v.add(prefix + attr);

                } else {
                    /*LogDoc
                     *
                     * @phase retrieve ldap attr
                     * @reason failed to get registered object class
                     * @message DBRegistry: <attr> is not registered
                     */
                    logger.error("LDAPRegistry: " + CMS.getLogMessage("CMSCORE_DBS_ATTR_NOT_REGISTER", attr));
                    throw new DBException(CMS.getLogMessage("CMSCORE_DBS_ATTR_NOT_REGISTER", attr));
                }
            }
        }

        if (v.size() == 0)
            return null;

        String ldapAttrs[] = new String[v.size()];
        v.toArray(ldapAttrs);

        return ldapAttrs;
    }

    /**
     * Creates attribute set from object.
     */
    @Override
    public LDAPAttributeSet createLDAPAttributeSet(IDBObj obj) throws EBaseException {

        Enumeration<String> e = obj.getSerializableAttrNames();
        LDAPAttributeSet attrs = new LDAPAttributeSet();

        // add object class to attribute set
        String className = ((Object) obj).getClass().getName();
        String[] ocNames = mOCclassNames.get(className);
        for (String ocName : ocNames) {
            logger.debug("LDAPRegistry: Adding object class " + ocName);
        }
        attrs.add(new LDAPAttribute("objectclass", ocNames));

        while (e.hasMoreElements()) {
            String name = e.nextElement();
            Object value = obj.get(name);

            if (value == null) {
                logger.debug("LDAPRegistry: Skipping empty attribute " + name);
            } else {
                logger.debug("LDAPRegistry: Mapping attribute " + name);
                mapObject(obj, name, value, attrs);
            }
        }

        return attrs;
    }

    /**
     * Creates object from attribute set.
     */
    @Override
    public IDBObj createObject(LDAPAttributeSet attrs)
            throws DBException {
        // map object class attribute to object
        LDAPAttribute attr = attrs.getAttribute("objectclass");
        if (attr == null) {
            throw new DBException(CMS.getLogMessage("CMS_DBS_MISSING_OBJECT_CLASS"));
        }

        attrs.remove("objectclass");

        // sort the object class values

        String[] s = attr.getStringValueArray();
        String sorted = sortAndConcate(s).toLowerCase();
        NameAndObject no = mOCldapNames.get(sorted);

        if (no == null) {
            throw new DBException(
                    CMS.getUserMessage("CMS_DBS_INVALID_CLASS_NAME", sorted));
        }
        Class<?> c = (Class<?>) no.getObject();

        try {
            IDBObj obj = (IDBObj) c.getDeclaredConstructor().newInstance();
            Enumeration<String> ee = obj.getSerializableAttrNames();

            while (ee.hasMoreElements()) {
                String oname = ee.nextElement();
                DBAttrMapper mapper = mAttrufNames.get(oname.toLowerCase());

                if (mapper == null) {
                    throw new DBException(
                            CMS.getUserMessage("CMS_DBS_NO_MAPPER_FOUND", oname));
                }
                mapper.mapLDAPAttributeSetToObject(attrs,
                        oname, obj);
            }
            return obj;
        } catch (Exception e) {

            /*LogDoc
             *
             * @phase create ldap attr
             * @reason failed to create object class
             * @message DBRegistry: <attr> is not registered
             */
            logger.error("LDAPRegistry: " + CMS.getUserMessage("CMS_DBS_INVALID_ATTRS") + ": " + e.getMessage(), e);
            throw new DBException(CMS.getUserMessage("CMS_DBS_INVALID_ATTRS") + ": " + e.getMessage(), e);
        }
    }

    /**
     * Sorts and concate given strings.
     */
    private String sortAndConcate(String s[]) {
        Vector<String> v = new Vector<>();

        // sort it first
        for (int i = 0; i < s.length; i++) {
            for (int j = 0; j < v.size(); j++) {
                String t = v.elementAt(j);

                if (s[i].compareTo(t) < 0) {
                    v.insertElementAt(s[i], j);
                    break;
                }
            }
            if (i != (v.size() - 1))
                v.addElement(s[i]);
        }

       return inStringFormat(v);
    }
}

/**
 * Just a convenient container class.
 */
class NameAndObject {

    private String mN = null;
    private Object mO = null;

    public NameAndObject(String name, Object o) {
        mN = name;
        mO = o;
    }

    public String getName() {
        return mN;
    }

    public Object getObject() {
        return mO;
    }
}
