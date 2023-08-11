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

import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Set;
import java.util.Vector;

import org.mozilla.jss.netscape.security.x509.CertificateSubjectName;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.EDBException;
import com.netscape.certsrv.dbs.Modification;
import com.netscape.certsrv.dbs.ModificationSet;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cmscore.dbs.DBRecord;
import com.netscape.cmscore.dbs.DBRegistry;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.dbs.DateMapper;
import com.netscape.cmscore.dbs.StringMapper;

/**
 * A request record is the stored version of a request.
 * It has a set of attributes that are mapped into LDAP
 * attributes for actual directory operations.
 */
public class RequestRecord extends DBRecord {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(RequestRecord.class);

    public final static String ATTR_REQUEST_ID = "requestId";
    public final static String ATTR_REQUEST_STATE = "requestState";
    public final static String ATTR_CREATE_TIME = "requestCreateTime";
    public final static String ATTR_MODIFY_TIME = "requestModifyTime";
    public final static String ATTR_SOURCE_ID = "requestSourceId";
    public final static String ATTR_REQUEST_OWNER = "requestOwner";
    public final static String ATTR_REQUEST_TYPE = "requestType";

    // Placeholder for ExtAttr data.  this attribute is not in LDAP, but
    // is used to trigger the ExtAttrDynMapper during conversion between LDAP
    // and the RequestRecord.
    public final static String ATTR_EXT_DATA = "requestExtData";

    public final static String ATTR_REALM = "realm";

    RequestId mRequestId;
    RequestStatus mRequestState;
    Date mCreateTime;
    Date mModifyTime;
    String mSourceId;
    String mOwner;
    String mRequestType;
    Hashtable<String, Object> mExtData;
    String realm;

    /**
     * Gets the request ID.
     *
     * @return request ID
     */
    public RequestId getRequestId() {
        return mRequestId;
    }

    /**
     * Gets attribute names of the request.
     *
     * @return list of attribute names
     */
    public Enumeration<String> getAttrNames() {
        return mAttrTable.keys();
    }

    /**
     * Gets the request attribute value by the name.
     *
     * @param name attribute name
     * @return attribute value
     */
    @Override
    public Object get(String name) {
        if (name.equals(ATTR_REQUEST_ID)) {
            return mRequestId;

        } else if (name.equals(ATTR_REQUEST_STATE)) {
            return mRequestState;

        } else if (name.equals(ATTR_REQUEST_TYPE)) {
            return mRequestType;

        } else if (name.equals(ATTR_MODIFY_TIME)) {
            return mModifyTime;

        } else if (name.equals(ATTR_CREATE_TIME)) {
            return mCreateTime;

        } else if (name.equals(ATTR_SOURCE_ID)) {
            return mSourceId;

        } else if (name.equals(ATTR_REQUEST_OWNER)) {
            return mOwner;

        } else if (name.equals(ATTR_EXT_DATA)) {
            return mExtData;

        } else if (name.equals(ATTR_REALM)) {
            return realm;

        } else {
            RequestAttr ra = mAttrTable.get(name);
            if (ra != null) {
                return ra.get(this);
            }
        }

        return null;
    }

    /**
     * Sets new attribute for the request.
     *
     * @param name attribute name
     * @param o attribute value
     */
    @Override
    @SuppressWarnings("unchecked")
    public void set(String name, Object o) {
        if (name.equals(ATTR_REQUEST_ID)) {
            mRequestId = (RequestId) o;

        } else if (name.equals(ATTR_REQUEST_STATE)) {
            mRequestState = (RequestStatus) o;

        } else if (name.equals(ATTR_REQUEST_TYPE)) {
            mRequestType = (String) o;

        } else if (name.equals(ATTR_CREATE_TIME)) {
            mCreateTime = (Date) o;

        } else if (name.equals(ATTR_MODIFY_TIME)) {
            mModifyTime = (Date) o;

        } else if (name.equals(ATTR_SOURCE_ID)) {
            mSourceId = (String) o;

        } else if (name.equals(ATTR_REQUEST_OWNER)) {
            mOwner = (String) o;

        } else if (name.equals(ATTR_REALM)) {
            realm = (String) o;

        } else if (name.equals(ATTR_EXT_DATA)) {
            mExtData = (Hashtable<String, Object>) o;

        } else {
            RequestAttr ra = mAttrTable.get(name);
            if (ra != null) {
                ra.set(this, o);
            }
        }
    }

    /**
     * Removes attribute from the request.
     *
     * @param name attribute name
     */
    @Override
    public void delete(String name)
            throws EBaseException {
        throw new EBaseException("Invalid call to delete");
    }

    /**
     * Gets attribute list of the request.
     *
     * @return attribute list
     */
    @Override
    public Enumeration<String> getElements() {
        return mAttrs.elements();
    }

    // IDBObj.getSerializableAttrNames
    @Override
    public Enumeration<String> getSerializableAttrNames() {
        return mAttrs.elements();
    }

    // copy values from r to the local record
    void add(Request r) throws EBaseException {
        add(r, null);
    }

    void add(Request r, Set<String> excludedLdapAttrs) throws EBaseException {
        // Collect the values for the record
        mRequestId = r.getRequestId();
        mRequestType = r.getRequestType();
        mRequestState = r.getRequestStatus();
        mSourceId = r.getSourceId();
        mOwner = r.getRequestOwner();
        mCreateTime = r.getCreationTime();
        mModifyTime = r.getModificationTime();
        realm = r.getRealm();
        mExtData = loadExtDataFromRequest(r, excludedLdapAttrs);

        for (int i = 0; i < mRequestA.length; i++) {
            mRequestA[i].add(r, this);
        }
    }

    void read(Request r) throws EBaseException {
        r.setRequestStatus(mRequestState);
        r.setSourceId(mSourceId);
        r.setRequestOwner(mOwner);
        r.setModificationTime(mModifyTime);
        r.setCreationTime(mCreateTime);
        r.setRealm(realm);
        storeExtDataIntoRequest(r);

        for (int i = 0; i < mRequestA.length; i++) {
            mRequestA[i].read(r, this);
        }
    }

    static void mod(ModificationSet mods, Request r) throws EBaseException {
        mod(mods, r, null);
    }

    static void mod(ModificationSet mods, Request r, Set<String> excludedLdapAttrs) throws EBaseException {
        //
        mods.add(ATTR_REQUEST_STATE, Modification.MOD_REPLACE, r.getRequestStatus());
        mods.add(ATTR_SOURCE_ID, Modification.MOD_REPLACE, r.getSourceId());
        mods.add(ATTR_REQUEST_OWNER, Modification.MOD_REPLACE, r.getRequestOwner());
        mods.add(ATTR_MODIFY_TIME, Modification.MOD_REPLACE, r.getModificationTime());
        mods.add(ATTR_EXT_DATA, Modification.MOD_REPLACE, loadExtDataFromRequest(r, excludedLdapAttrs));

        // TODO(alee) - realm cannot be changed once set.  Can the code be refactored to eliminate
        // the next few lines?
        if (r.getRealm() != null) {
            mods.add(ATTR_REALM, Modification.MOD_REPLACE, r.getRealm());
        }

        for (int i = 0; i < mRequestA.length; i++) {
            mRequestA[i].mod(mods, r);
        }
    }

    static void register(DBSubsystem dbSubsystem)
            throws EDBException {
        DBRegistry reg = dbSubsystem.getRegistry();

        reg.registerObjectClass(RequestRecord.class.getName(), mOC);

        reg.registerAttribute(ATTR_REQUEST_ID, new RequestIdMapper());
        reg.registerAttribute(ATTR_REQUEST_STATE, new RequestStateMapper());
        reg.registerAttribute(ATTR_CREATE_TIME, new DateMapper(Schema.LDAP_ATTR_CREATE_TIME));
        reg.registerAttribute(ATTR_MODIFY_TIME, new DateMapper(Schema.LDAP_ATTR_MODIFY_TIME));
        reg.registerAttribute(ATTR_SOURCE_ID, new StringMapper(Schema.LDAP_ATTR_SOURCE_ID));
        reg.registerAttribute(ATTR_REQUEST_OWNER, new StringMapper(Schema.LDAP_ATTR_REQUEST_OWNER));
        reg.registerAttribute(ATTR_REALM, new StringMapper(Schema.LDAP_ATTR_REALM));
        ExtAttrDynMapper extAttrMapper = new ExtAttrDynMapper();
        reg.registerAttribute(ATTR_EXT_DATA, extAttrMapper);
        reg.registerDynamicMapper(extAttrMapper);

        for (int i = 0; i < mRequestA.length; i++) {
            RequestAttr ra = mRequestA[i];
            reg.registerAttribute(ra.mAttrName, ra.mMapper);
        }
    }

    protected static final String mOC[] =
        { Schema.LDAP_OC_TOP, Schema.LDAP_OC_REQUEST, Schema.LDAP_OC_EXTENSIBLE };

    protected static Hashtable<String, Object> loadExtDataFromRequest(
            Request r,
            Set<String> excludedLdapAttrs) throws EBaseException {

        Hashtable<String, Object> h = new Hashtable<>();
        String reqType = r.getExtDataInString("cert_request_type");
        if (reqType == null || reqType.equals("")) {
            // where CMC puts it
            reqType = r.getExtDataInString("auth_token.cert_request_type");
        }

        Enumeration<String> e = r.getExtDataKeys();
        while (e.hasMoreElements()) {
            String key = e.nextElement();
            if (r.isSimpleExtDataValue(key)) {
                if (key.equals("req_x509info")) {
                    // extract subjectName if possible here
                    // if already there, skip it
                    String subjectName = r.getExtDataInString("req_subject_name");
                    if (subjectName == null || subjectName.equals("")) {
                        X509CertInfo info = r.getExtDataInCertInfo(Request.CERT_INFO);
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
                    (excludedLdapAttrs != null && excludedLdapAttrs.contains(key))) {
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
    protected void storeExtDataIntoRequest(Request r) throws EBaseException {
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

    public Request toRequest() throws EBaseException {
        Request record = new Request(mRequestId);
        read(record);
        return record;
    }

    protected static Vector<String> mAttrs = new Vector<>();

    static Hashtable<String, RequestAttr> mAttrTable = new Hashtable<>();

    /*
     * This table contains attribute handlers for attributes
     * of the request.  These attributes are ones that are stored
     * apart from the generic name/value pairs supported by the get/set
     * interface plus the hashtable for the name/value pairs themselves.
     *
     * NOTE: Eventually, all attributes should be done here.  Currently
     *   only the last ones added are implemented this way.
     */
    static RequestAttr[] mRequestA = { new RequestType() };

    static {
        mAttrs.add(ATTR_REQUEST_ID);
        mAttrs.add(ATTR_REQUEST_STATE);
        mAttrs.add(ATTR_CREATE_TIME);
        mAttrs.add(ATTR_MODIFY_TIME);
        mAttrs.add(ATTR_SOURCE_ID);
        mAttrs.add(ATTR_REQUEST_OWNER);
        mAttrs.add(ATTR_REALM);
        mAttrs.add(ATTR_EXT_DATA);

        for (int i = 0; i < mRequestA.length; i++) {
            RequestAttr ra = mRequestA[i];

            mAttrs.add(ra.mAttrName);
            mAttrTable.put(ra.mAttrName, ra);
        }
    }

}
