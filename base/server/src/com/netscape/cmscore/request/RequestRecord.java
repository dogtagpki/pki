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
package com.netscape.cmscore.request;

import java.math.BigInteger;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.mozilla.jss.netscape.security.x509.CertificateSubjectName;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.EDBException;
import com.netscape.certsrv.dbs.IDBAttrMapper;
import com.netscape.certsrv.dbs.IDBObj;
import com.netscape.certsrv.dbs.IDBRegistry;
import com.netscape.certsrv.dbs.Modification;
import com.netscape.certsrv.dbs.ModificationSet;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestRecord;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.certsrv.request.ldap.IRequestMod;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.dbs.BigIntegerMapper;
import com.netscape.cmscore.dbs.DateMapper;
import com.netscape.cmscore.dbs.IDBSubsystem;
import com.netscape.cmscore.dbs.StringMapper;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;

//
// A request record is the stored version of a request.
// It has a set of attributes that are mapped into LDAP
// attributes for actual directory operations.
//
public class RequestRecord
        extends ARequestRecord
        implements IRequestRecord, IDBObj {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(RequestRecord.class);
    private static final long serialVersionUID = 8044665107558872084L;

    public RequestId getRequestId() {
        return mRequestId;
    }

    public Enumeration<String> getAttrNames() {
        return mAttrTable.keys();
    }

    // IDBObj.get
    public Object get(String name) {
        if (name.equals(IRequestRecord.ATTR_REQUEST_ID))
            return mRequestId;
        else if (name.equals(IRequestRecord.ATTR_REQUEST_STATE))
            return mRequestState;
        else if (name.equals(IRequestRecord.ATTR_REQUEST_TYPE))
            return mRequestType;
        else if (name.equals(IRequestRecord.ATTR_MODIFY_TIME))
            return mModifyTime;
        else if (name.equals(IRequestRecord.ATTR_CREATE_TIME))
            return mCreateTime;
        else if (name.equals(IRequestRecord.ATTR_SOURCE_ID))
            return mSourceId;
        else if (name.equals(IRequestRecord.ATTR_REQUEST_OWNER))
            return mOwner;
        else if (name.equals(IRequestRecord.ATTR_EXT_DATA))
            return mExtData;
        else if (name.equals(IRequestRecord.ATTR_REALM))
            return realm;
        else {
            RequestAttr ra = mAttrTable.get(name);

            if (ra != null)
                return ra.get(this);
        }

        return null;
    }

    // IDBObj.set
    @SuppressWarnings("unchecked")
    public void set(String name, Object o) {
        if (name.equals(IRequestRecord.ATTR_REQUEST_ID))
            mRequestId = (RequestId) o;
        else if (name.equals(IRequestRecord.ATTR_REQUEST_STATE))
            mRequestState = (RequestStatus) o;
        else if (name.equals(IRequestRecord.ATTR_REQUEST_TYPE))
            mRequestType = (String) o;
        else if (name.equals(IRequestRecord.ATTR_CREATE_TIME))
            mCreateTime = (Date) o;
        else if (name.equals(IRequestRecord.ATTR_MODIFY_TIME))
            mModifyTime = (Date) o;
        else if (name.equals(IRequestRecord.ATTR_SOURCE_ID))
            mSourceId = (String) o;
        else if (name.equals(IRequestRecord.ATTR_REQUEST_OWNER))
            mOwner = (String) o;
        else if (name.equals(IRequestRecord.ATTR_REALM))
            realm = (String) o;
        else if (name.equals(IRequestRecord.ATTR_EXT_DATA))
            mExtData = (Hashtable<String, Object>) o;
        else {
            RequestAttr ra = mAttrTable.get(name);

            if (ra != null)
                ra.set(this, o);
        }
    }

    // IDBObj.delete
    public void delete(String name)
            throws EBaseException {
        throw new EBaseException("Invalid call to delete");
    }

    // IDBObj.getElements
    public Enumeration<String> getElements() {
        return mAttrs.elements();
    }

    // IDBObj.getSerializableAttrNames
    public Enumeration<String> getSerializableAttrNames() {
        return mAttrs.elements();
    }

    // copy values from r to the local record
    void add(IRequest r) throws EBaseException {
        // Collect the values for the record
        mRequestId = r.getRequestId();
        mRequestType = r.getRequestType();
        mRequestState = r.getRequestStatus();
        mSourceId = r.getSourceId();
        mOwner = r.getRequestOwner();
        mCreateTime = r.getCreationTime();
        mModifyTime = r.getModificationTime();
        realm = r.getRealm();
        mExtData = loadExtDataFromRequest(r);

        for (int i = 0; i < mRequestA.length; i++) {
            mRequestA[i].add(r, this);
        }
    }

    void read(IRequestMod a, IRequest r) throws EBaseException {
        a.modRequestStatus(r, mRequestState);
        r.setSourceId(mSourceId);
        r.setRequestOwner(mOwner);
        a.modModificationTime(r, mModifyTime);
        a.modCreationTime(r, mCreateTime);
        r.setRealm(realm);
        storeExtDataIntoRequest(r);

        for (int i = 0; i < mRequestA.length; i++) {
            mRequestA[i].read(a, r, this);
        }
    }

    static void mod(ModificationSet mods, IRequest r) throws EBaseException {
        //
        mods.add(IRequestRecord.ATTR_REQUEST_STATE,
                Modification.MOD_REPLACE, r.getRequestStatus());

        mods.add(IRequestRecord.ATTR_SOURCE_ID,
                Modification.MOD_REPLACE, r.getSourceId());

        mods.add(IRequestRecord.ATTR_REQUEST_OWNER,
                Modification.MOD_REPLACE, r.getRequestOwner());

        mods.add(IRequestRecord.ATTR_MODIFY_TIME,
                Modification.MOD_REPLACE, r.getModificationTime());

        mods.add(IRequestRecord.ATTR_EXT_DATA,
                Modification.MOD_REPLACE, loadExtDataFromRequest(r));

        // TODO(alee) - realm cannot be changed once set.  Can the code be refactored to eliminate
        // the next few lines?
        if (r.getRealm() != null) {
            mods.add(IRequestRecord.ATTR_REALM, Modification.MOD_REPLACE, r.getRealm());
        }

        for (int i = 0; i < mRequestA.length; i++) {
            mRequestA[i].mod(mods, r);
        }
    }

    static void register(IDBSubsystem db)
            throws EDBException {
        IDBRegistry reg = db.getRegistry();

        reg.registerObjectClass(RequestRecord.class.getName(), mOC);

        reg.registerAttribute(IRequestRecord.ATTR_REQUEST_ID, new RequestIdMapper());
        reg.registerAttribute(IRequestRecord.ATTR_REQUEST_STATE, new RequestStateMapper());
        reg.registerAttribute(IRequestRecord.ATTR_CREATE_TIME,
                new DateMapper(Schema.LDAP_ATTR_CREATE_TIME));
        reg.registerAttribute(IRequestRecord.ATTR_MODIFY_TIME,
                new DateMapper(Schema.LDAP_ATTR_MODIFY_TIME));
        reg.registerAttribute(IRequestRecord.ATTR_SOURCE_ID,
                new StringMapper(Schema.LDAP_ATTR_SOURCE_ID));
        reg.registerAttribute(IRequestRecord.ATTR_REQUEST_OWNER,
                new StringMapper(Schema.LDAP_ATTR_REQUEST_OWNER));
        reg.registerAttribute(IRequestRecord.ATTR_REALM,
                new StringMapper(Schema.LDAP_ATTR_REALM));
        ExtAttrDynMapper extAttrMapper = new ExtAttrDynMapper();
        reg.registerAttribute(IRequestRecord.ATTR_EXT_DATA, extAttrMapper);
        reg.registerDynamicMapper(extAttrMapper);

        for (int i = 0; i < mRequestA.length; i++) {
            RequestAttr ra = mRequestA[i];

            reg.registerAttribute(ra.mAttrName, ra.mMapper);
        }
    }

    protected static final String mOC[] =
        { Schema.LDAP_OC_TOP, Schema.LDAP_OC_REQUEST, Schema.LDAP_OC_EXTENSIBLE };

    protected static Hashtable<String, Object> loadExtDataFromRequest(IRequest r) throws EBaseException {
        Hashtable<String, Object> h = new Hashtable<String, Object>();
        String reqType = r.getExtDataInString("cert_request_type");
        if (reqType == null || reqType.equals("")) {
            // where CMC puts it
            reqType = r.getExtDataInString("auth_token.cert_request_type");
        }
        CMSEngine engine = CMS.getCMSEngine();
        Enumeration<String> e = r.getExtDataKeys();
        while (e.hasMoreElements()) {
            String key = e.nextElement();
            if (r.isSimpleExtDataValue(key)) {
                if (key.equals("req_x509info")) {
                    // extract subjectName if possible here
                    // if already there, skip it
                    String subjectName = r.getExtDataInString("req_subject_name");
                    if (subjectName == null || subjectName.equals("")) {
                        X509CertInfo info = r.getExtDataInCertInfo(IRequest.CERT_INFO);
                        logger.debug("RequestRecord.loadExtDataFromRequest: missing subject name. Processing extracting subjectName from req_x509info");
                        try {
                            CertificateSubjectName subjName = (CertificateSubjectName) info.get(X509CertInfo.SUBJECT);
                            if (subjName != null) {
                                logger.debug("RequestRecord.loadExtDataFromRequest: got subjName");
                                h.put("req_subject_name", subjName.toString());
                            }
                        } catch (Exception es) {
                          //if failed, then no other way to get subject name.
                          //so be it
                        }
                    }/* else { //this is the common case
                        logger.debug("RequestRecord.loadExtDataFromRequest: subject name already exists, no action needed");
                    }*/
                }
                if (reqType != null &&
                    (reqType.equals("crmf") || reqType.equals("cmc-crmf")) &&
                        engine.isExcludedLdapAttr(key)) {
                    // logger.debug("RequestRecord.loadExtDataFromRequest: found excluded attr; key=" + key);
                    continue;
                }
                h.put(key, r.getExtDataInString(key));
            } else {
                h.put(key, r.getExtDataInHashtable(key));
            }
        }

        return h;
    }

    @SuppressWarnings("unchecked")
    protected void storeExtDataIntoRequest(IRequest r) throws EBaseException {
        Enumeration<String> e = mExtData.keys();
        while (e.hasMoreElements()) {
            String key = e.nextElement();
            Object value = mExtData.get(key);
            if (value instanceof String) {
                r.setExtData(key, (String) value);
            } else if (value instanceof Hashtable) {
                r.setExtData(key, (Hashtable<String, String>) value);
            } else {
                throw new EDBException("Illegal data value in RequestRecord: " +
                        r.toString());
            }
        }
    }

    protected static Vector<String> mAttrs = new Vector<String>();

    static Hashtable<String, RequestAttr> mAttrTable = new Hashtable<String, RequestAttr>();

    /*
     * This table contains attribute handlers for attributes
     * of the request.  These attributes are ones that are stored
     * apart from the generic name/value pairs supported by the get/set
     * interface plus the hashtable for the name/value pairs themselves.
     *
     * NOTE: Eventually, all attributes should be done here.  Currently
     *   only the last ones added are implemented this way.
     */
    static RequestAttr mRequestA[] = {

    new RequestAttr(IRequest.ATTR_REQUEST_TYPE,
                new StringMapper(Schema.LDAP_ATTR_REQUEST_TYPE)) {
        void set(ARequestRecord r, Object o) {
            r.mRequestType = (String) o;
        }

        Object get(ARequestRecord r) {
            return r.mRequestType;
        }

        void read(IRequestMod a, IRequest r, ARequestRecord rr) {
            r.setRequestType(rr.mRequestType);
        }

        void add(IRequest r, ARequestRecord rr) {
            rr.mRequestType = r.getRequestType();
        }

        void mod(ModificationSet mods, IRequest r) {
            addmod(mods, r.getRequestType());
        }
    }

    };
    static {
        mAttrs.add(IRequestRecord.ATTR_REQUEST_ID);
        mAttrs.add(IRequestRecord.ATTR_REQUEST_STATE);
        mAttrs.add(IRequestRecord.ATTR_CREATE_TIME);
        mAttrs.add(IRequestRecord.ATTR_MODIFY_TIME);
        mAttrs.add(IRequestRecord.ATTR_SOURCE_ID);
        mAttrs.add(IRequestRecord.ATTR_REQUEST_OWNER);
        mAttrs.add(IRequestRecord.ATTR_REALM);
        mAttrs.add(IRequestRecord.ATTR_EXT_DATA);

        for (int i = 0; i < mRequestA.length; i++) {
            RequestAttr ra = mRequestA[i];

            mAttrs.add(ra.mAttrName);
            mAttrTable.put(ra.mAttrName, ra);
        }
    }

}

//
// A mapper between an request state object and
// its LDAP attribute representation
// <P>
//
// @author thayes
// @version $Revision$ $Date$
//
class RequestStateMapper
        implements IDBAttrMapper {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(RequestStateMapper.class);

    public Enumeration<String> getSupportedLDAPAttributeNames() {
        return mAttrs.elements();
    }

    public void mapObjectToLDAPAttributeSet(IDBObj parent,
            String name, Object obj, LDAPAttributeSet attrs) throws EBaseException {
        if (obj == null) {
            throw new EBaseException(CMS.getUserMessage("CMS_DBS_SERIALIZE_FAILED", name));
        }
        RequestStatus rs = (RequestStatus) obj;

        attrs.add(new LDAPAttribute(Schema.LDAP_ATTR_REQUEST_STATE,
                rs.toString()));
    }

    public void mapLDAPAttributeSetToObject(LDAPAttributeSet attrs,
            String name, IDBObj parent)
            throws EBaseException {
        LDAPAttribute attr = attrs.getAttribute(Schema.LDAP_ATTR_REQUEST_STATE);

        if (attr == null)
            throw new EBaseException("schema violation");

        String value = attr.getStringValues().nextElement();

        parent.set(name, RequestStatus.fromString(value));
    }

    public String mapSearchFilter(String name, String op, String value) {
        return Schema.LDAP_ATTR_REQUEST_STATE + op + value;
    }

    protected final static Vector<String> mAttrs = new Vector<String>();

    static {
        mAttrs.add(Schema.LDAP_ATTR_REQUEST_STATE);
    }
}

//
// A mapper between an request id object and
// its LDAP attribute representation
// <P>
//
// @author thayes
// @version $Revision$ $Date$
//
class RequestIdMapper
        implements IDBAttrMapper {
    // IDBAttrMapper methods

    //
    //
    public Enumeration<String> getSupportedLDAPAttributeNames() {
        return mAttrs.elements();
    }

    //
    public void mapObjectToLDAPAttributeSet(IDBObj parent,
            String name, Object obj, LDAPAttributeSet attrs) throws EBaseException {
        if (obj == null) {
            throw new EBaseException(CMS.getUserMessage("CMS_DBS_SERIALIZE_FAILED", name));
        }
        RequestId rid = (RequestId) obj;

        String v = BigIntegerMapper.BigIntegerToDB(new BigInteger(rid.toString()));

        attrs.add(new LDAPAttribute(Schema.LDAP_ATTR_REQUEST_ID, v));
    }

    public void mapLDAPAttributeSetToObject(LDAPAttributeSet attrs,
            String name, IDBObj parent)
            throws EBaseException {
        LDAPAttribute attr = attrs.getAttribute(Schema.LDAP_ATTR_REQUEST_ID);

        if (attr == null)
            throw new EBaseException("schema violation");

        String value = attr.getStringValues().nextElement();

        parent.set(name, new RequestId(
                BigIntegerMapper.BigIntegerFromDB(value).toString()));
    }

    public String mapSearchFilter(String name, String op, String value) throws EBaseException {
        String v = null;

        try {
            v = BigIntegerMapper.BigIntegerToDB(new BigInteger(value));
        } catch (NumberFormatException e) {
            v = value;
        }
        return Schema.LDAP_ATTR_REQUEST_ID + op + v;
    }

    protected final static Vector<String> mAttrs = new Vector<String>();

    static {
        mAttrs.add(Schema.LDAP_ATTR_REQUEST_ID);
    }
}
