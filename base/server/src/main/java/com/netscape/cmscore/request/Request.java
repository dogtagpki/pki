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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Locale;
import java.util.Set;
import java.util.Vector;

import org.dogtagpki.server.authentication.AuthToken;
import org.mozilla.jss.netscape.security.util.DerInputStream;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.CertificateSubjectName;
import org.mozilla.jss.netscape.security.x509.RevokedCertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509ExtensionException;

import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.IAttrSet;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;

/**
 * Request - implementation of the IRequest interface.  This
 * version is returned by ARequestQueue (and its derivatives)
 */
public class Request implements IRequest {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(Request.class);

    protected RequestId mRequestId;
    protected RequestStatus mRequestStatus;
    protected String mSourceId;
    protected String mSource;
    protected String mOwner;
    protected String mRequestType;
    protected String mContext; // string for now.
    protected String realm;
    protected ExtDataHashtable<Object> mExtData = new ExtDataHashtable<>();

    Date mCreationTime = new Date();
    Date mModificationTime = new Date();

    public Request(RequestId id) {
        mRequestId = id;
        setRequestStatus(RequestStatus.BEGIN);
    }

    // IRequest.getRequestId
    @Override
    public RequestId getRequestId() {
        return mRequestId;
    }

    // IRequest.getRequestStatus
    @Override
    public RequestStatus getRequestStatus() {
        return mRequestStatus;
    }

    // Obsolete
    @Override
    public void setRequestStatus(RequestStatus s) {
        mRequestStatus = s;
        // expose request status so that we can do predicate upon it
        setExtData(IRequest.REQ_STATUS, s.toString());
    }

    @Override
    public boolean isSuccess() {
        Integer result = getExtDataInInteger(IRequest.RESULT);

        if (result != null && result.equals(IRequest.RES_SUCCESS))
            return true;
        else
            return false;
    }

    @Override
    public String getError(Locale locale) {
        return getExtDataInString(IRequest.ERROR);
    }

    @Override
    public String getErrorCode(Locale locale) {
        return getExtDataInString(IRequest.ERROR_CODE);
    }

    // IRequest.getSourceId
    @Override
    public String getSourceId() {
        return mSourceId;
    }

    // IRequest.setSourceId
    @Override
    public void setSourceId(String id) {
        mSourceId = id;
    }

    // IRequest.getRequestOwner
    @Override
    public String getRequestOwner() {
        return mOwner;
    }

    // IRequest.setRequestOwner
    @Override
    public void setRequestOwner(String id) {
        mOwner = id;
    }

    // IRequest.getRequestType
    @Override
    public String getRequestType() {
        return mRequestType;
    }

    // IRequest.setRequestType
    @Override
    public void setRequestType(String type) {
        mRequestType = type;
        setExtData(IRequest.REQ_TYPE, type);
    }

    // IRequest.getRequestVersion
    @Override
    public String getRequestVersion() {
        return getExtDataInString(IRequest.REQ_VERSION);
    }

    // IRequest.getCreationTime
    @Override
    public Date getCreationTime() {
        return mCreationTime;
    }

    @Override
    public void setCreationTime(Date date) {
        mCreationTime = date;
    }

    @Override
    public String getContext() {
        return mContext;
    }

    @Override
    public void setContext(String ctx) {
        mContext = ctx;
    }

    // IRequest.getModificationTime
    @Override
    public Date getModificationTime() {
        return mModificationTime;
    }

    @Override
    public void setModificationTime(Date date) {
        mModificationTime = date;
    }

    /**
     * this isn't that efficient but will do for now.
     */
    @Override
    public void copyContents(IRequest req) {
        Enumeration<String> e = req.getExtDataKeys();
        while (e.hasMoreElements()) {
            String key = e.nextElement();
            if (!key.equals(IRequest.ISSUED_CERTS) &&
                    !key.equals(IRequest.ERRORS) &&
                    !key.equals(IRequest.REMOTE_REQID)) {
                if (req.isSimpleExtDataValue(key)) {
                    setExtData(key, req.getExtDataInString(key));
                } else {
                    setExtData(key, req.getExtDataInHashtable(key));
                }
            }
        }
    }

    /**
     * This function used to check that the keys obeyed LDAP attribute name
     * syntax rules. Keys are being encoded now, so it is changed to just
     * filter out null and empty string keys.
     *
     * @param key The key to check
     * @return false if invalid
     */
    protected boolean isValidExtDataKey(String key) {
        return key != null &&
                (!key.equals(""));
    }

    protected boolean isValidExtDataHashtableValue(Hashtable<String, String> hash) {
        if (hash == null) {
            return false;
        }
        Enumeration<String> keys = hash.keys();
        while (keys.hasMoreElements()) {
            Object key = keys.nextElement();
            if (!((key instanceof String) && isValidExtDataKey((String) key))) {
                return false;
            }
            /*
             * 	TODO  should the Value type be String?
             */
            Object value = hash.get(key);
            if (!(value instanceof String)) {
                return false;
            }
        }

        return true;
    }

    @Override
    public boolean setExtData(String key, String value) {
        if (!isValidExtDataKey(key)) {
            return false;
        }
        if (value == null) {
            return false;
        }

        mExtData.put(key, value);
        return true;
    }

    @Override
    public boolean setExtData(String key, Hashtable<String, String> value) {
        if (!(isValidExtDataKey(key) && isValidExtDataHashtableValue(value))) {
            return false;
        }

        mExtData.put(key, new ExtDataHashtable<>(value));
        return true;
    }

    @Override
    public boolean isSimpleExtDataValue(String key) {
        return (mExtData.get(key) instanceof String);
    }

    @Override
    public String getExtDataInString(String key) {
        Object value = mExtData.get(key);
        if (value == null) {
            return null;
        }
        if (!(value instanceof String)) {
            return null;
        }
        return (String) value;
    }

    @Override
    @SuppressWarnings("unchecked")
    public Hashtable<String, String> getExtDataInHashtable(String key) {
        Object value = mExtData.get(key);
        if (value == null) {
            return null;
        }
        if (!(value instanceof Hashtable)) {
            return null;
        }
        return new ExtDataHashtable<>((Hashtable<String, String>) value);
    }

    @Override
    public Enumeration<String> getExtDataKeys() {
        return mExtData.keys();
    }

    @Override
    public void deleteExtData(String type) {
        mExtData.remove(type);
    }

    @Override
    public boolean setExtData(String key, String subkey, String value) {
        if (!(isValidExtDataKey(key) && isValidExtDataKey(subkey))) {
            return false;
        }
        if (isSimpleExtDataValue(key)) {
            return false;
        }
        if (value == null) {
            return false;
        }

        @SuppressWarnings("unchecked")
        Hashtable<String, String> existingValue = (Hashtable<String, String>) mExtData.get(key);
        if (existingValue == null) {
            existingValue = new ExtDataHashtable<>();
            mExtData.put(key, existingValue);
        }
        existingValue.put(subkey, value);
        return true;
    }

    @Override
    public String getExtDataInString(String key, String subkey) {
        Hashtable<String, String> value = getExtDataInHashtable(key);
        if (value == null) {
            return null;
        }
        return value.get(subkey);
    }

    @Override
    public boolean setExtData(String key, Integer value) {
        if (value == null) {
            return false;
        }
        return setExtData(key, value.toString());
    }

    @Override
    public Integer getExtDataInInteger(String key) {
        String strVal = getExtDataInString(key);
        if (strVal == null) {
            return null;
        }
        try {
            return Integer.valueOf(strVal);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    @Override
    public boolean setExtData(String key, Integer[] data) {
        if (data == null) {
            return false;
        }
        String[] stringArray = new String[data.length];
        for (int index = 0; index < data.length; index++) {
            stringArray[index] = data[index].toString();
        }
        return setExtData(key, stringArray);
    }

    @Override
    public Integer[] getExtDataInIntegerArray(String key) {
        String[] stringArray = getExtDataInStringArray(key);
        if (stringArray == null) {
            return null;
        }
        Integer[] intArray = new Integer[stringArray.length];
        for (int index = 0; index < stringArray.length; index++) {
            try {
                intArray[index] = Integer.valueOf(stringArray[index]);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return intArray;
    }

    @Override
    public boolean setExtData(String key, BigInteger value) {
        if (value == null) {
            return false;
        }
        return setExtData(key, value.toString());
    }

    @Override
    public BigInteger getExtDataInBigInteger(String key) {
        String strVal = getExtDataInString(key);
        if (strVal == null) {
            return null;
        }
        try {
            return new BigInteger(strVal);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    @Override
    public boolean setExtData(String key, BigInteger[] data) {
        if (data == null) {
            return false;
        }
        String[] stringArray = new String[data.length];
        for (int index = 0; index < data.length; index++) {
            stringArray[index] = data[index].toString();
        }
        return setExtData(key, stringArray);
    }

    @Override
    public BigInteger[] getExtDataInBigIntegerArray(String key) {
        String[] stringArray = getExtDataInStringArray(key);
        if (stringArray == null) {
            return null;
        }
        BigInteger[] intArray = new BigInteger[stringArray.length];
        for (int index = 0; index < stringArray.length; index++) {
            try {
                intArray[index] = new BigInteger(stringArray[index]);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return intArray;
    }

    @Override
    public boolean setExtData(String key, Throwable e) {
        if (e == null) {
            return false;
        }
        return setExtData(key, e.toString());
    }

    @Override
    public boolean setExtData(String key, byte[] data) {
        if (data == null) {
            return false;
        }
        return setExtData(key, Utils.base64encode(data, true));
    }

    @Override
    public byte[] getExtDataInByteArray(String key) {
        String value = getExtDataInString(key);
        if (value != null) {
            return Utils.base64decode(value);
        }
        return null;
    }

    @Override
    public boolean setExtData(String key, X509CertImpl data) {
        if (data == null) {
            return false;
        }
        try {
            return setExtData(key, data.getEncoded());
        } catch (CertificateEncodingException e) {
            return false;
        }
    }

    @Override
    public X509CertImpl getExtDataInCert(String key) {
        byte[] data = getExtDataInByteArray(key);
        if (data != null) {
            try {
                return new X509CertImpl(data);
            } catch (CertificateException e) {
                logger.warn("ARequestQueue: getExtDataInCert(): " + e.getMessage(), e);
                return null;
            }
        }
        return null;
    }

    @Override
    public boolean setExtData(String key, X509CertImpl[] data) {
        if (data == null) {
            return false;
        }
        String[] stringArray = new String[data.length];
        for (int index = 0; index < data.length; index++) {
            try {
                stringArray[index] = Utils.base64encode(data[index].getEncoded(), true);
            } catch (CertificateEncodingException e) {
                return false;
            }
        }
        return setExtData(key, stringArray);
    }

    @Override
    public X509CertImpl[] getExtDataInCertArray(String key) {
        String[] stringArray = getExtDataInStringArray(key);
        if (stringArray == null) {
            return null;
        }
        X509CertImpl[] certArray = new X509CertImpl[stringArray.length];
        for (int index = 0; index < stringArray.length; index++) {
            try {
                certArray[index] = new X509CertImpl(Utils.base64decode(stringArray[index]));
            } catch (CertificateException e) {
                logger.warn("ARequestQueue: getExtDataInCertArray(): " + e.getMessage(), e);
                return null;
            }
        }
        return certArray;
    }

    @Override
    public boolean setExtData(String key, X509CertInfo data) {
        if (data == null) {
            return false;
        }
        try {
            return setExtData(key, data.getEncodedInfo(true));
        } catch (CertificateEncodingException e) {
            return false;
        }
    }

    @Override
    public X509CertInfo getExtDataInCertInfo(String key) {
        byte[] data = getExtDataInByteArray(key);
        if (data != null) {
            try {
                return new X509CertInfo(data);
            } catch (CertificateException e) {
                logger.warn("ARequestQueue: getExtDataInCertInfo(): " + e.getMessage(), e);
                return null;
            }
        }
        return null;
    }

    @Override
    public boolean setExtData(String key, X509CertInfo[] data) {
        if (data == null) {
            return false;
        }
        String[] stringArray = new String[data.length];
        for (int index = 0; index < data.length; index++) {
            try {
                stringArray[index] = Utils.base64encode(data[index].getEncodedInfo(true), true);
            } catch (CertificateEncodingException e) {
                return false;
            }
        }
        return setExtData(key, stringArray);
    }

    @Override
    public X509CertInfo[] getExtDataInCertInfoArray(String key) {
        String[] stringArray = getExtDataInStringArray(key);
        if (stringArray == null) {
            return null;
        }
        X509CertInfo[] certArray = new X509CertInfo[stringArray.length];
        for (int index = 0; index < stringArray.length; index++) {
            try {
                certArray[index] = new X509CertInfo(Utils.base64decode(stringArray[index]));
            } catch (CertificateException e) {
                logger.warn("ARequestQueue: getExtDataInCertInfoArray(): " + e.getMessage(), e);
                return null;
            }
        }
        return certArray;
    }

    @Override
    public boolean setExtData(String key, RevokedCertImpl[] data) {
        if (data == null) {
            return false;
        }
        String[] stringArray = new String[data.length];
        for (int index = 0; index < data.length; index++) {
            try {
                stringArray[index] = Utils.base64encode(data[index].getEncoded(), true);
            } catch (CRLException e) {
                return false;
            }
        }
        return setExtData(key, stringArray);
    }

    @Override
    public RevokedCertImpl[] getExtDataInRevokedCertArray(String key) {
        String[] stringArray = getExtDataInStringArray(key);
        if (stringArray == null) {
            return null;
        }
        RevokedCertImpl[] certArray = new RevokedCertImpl[stringArray.length];
        for (int index = 0; index < stringArray.length; index++) {
            try {
                certArray[index] = new RevokedCertImpl(Utils.base64decode(stringArray[index]));
            } catch (CRLException e) {
                return null;
            } catch (X509ExtensionException e) {
                return null;
            }
        }
        return certArray;
    }

    @Override
    public boolean setExtData(String key, Vector<?> stringVector) {
        String[] stringArray;
        if (stringVector == null) {
            return false;
        }
        try {
            stringArray = stringVector.toArray(new String[0]);
        } catch (ArrayStoreException e) {
            return false;
        }
        return setExtData(key, stringArray);
    }

    @Override
    public Vector<String> getExtDataInStringVector(String key) {
        String[] stringArray = getExtDataInStringArray(key);
        if (stringArray == null) {
            return null;
        }
        return new Vector<>(Arrays.asList(stringArray));
    }

    @Override
    public boolean getExtDataInBoolean(String key, boolean defVal) {
        String val = getExtDataInString(key);
        if (val == null)
            return defVal;
        return val.equalsIgnoreCase("true") || val.equalsIgnoreCase("ON");
    }

    @Override
    public boolean getExtDataInBoolean(String prefix, String type, boolean defVal) {
        String val = getExtDataInString(prefix, type);
        if (val == null)
            return defVal;
        return val.equalsIgnoreCase("true") || val.equalsIgnoreCase("ON");
    }

    @Override
    public boolean setExtData(String key, IAuthToken data) {
        if (data == null) {
            return false;
        }
        Hashtable<String, String> hash = new Hashtable<>();
        Enumeration<String> keys = data.getElements();
        while (keys.hasMoreElements()) {
            try {
                String authKey = keys.nextElement();
                hash.put(authKey, data.getInString(authKey));
            } catch (ClassCastException e) {
                return false;
            }
        }
        return setExtData(key, hash);
    }

    @Override
    public IAuthToken getExtDataInAuthToken(String key) {
        Hashtable<String, String> hash = getExtDataInHashtable(key);
        if (hash == null) {
            return null;
        }
        AuthToken authToken = new AuthToken(null);
        Enumeration<String> keys = hash.keys();
        while (keys.hasMoreElements()) {
            try {
                String hashKey = keys.nextElement();
                authToken.set(hashKey, hash.get(hashKey));
            } catch (ClassCastException e) {
                return null;
            }
        }
        return authToken;
    }

    @Override
    public boolean setExtData(String key, CertificateExtensions data) {
        if (data == null) {
            return false;
        }
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        try {
            data.encode(byteStream);
        } catch (CertificateException e) {
            logger.warn("ARequestQueue: setExtData(): " + e.getMessage(), e);
            return false;
        } catch (IOException e) {
            logger.warn("ARequestQueue: setExtData(): " + e.getMessage(), e);
            return false;
        }
        return setExtData(key, byteStream.toByteArray());
    }

    @Override
    public CertificateExtensions getExtDataInCertExts(String key) {
        CertificateExtensions exts = null;
        byte[] extensionsData = getExtDataInByteArray(key);
        if (extensionsData != null) {
            exts = new CertificateExtensions();
            try {
                exts.decodeEx(new ByteArrayInputStream(extensionsData));
                // exts.decode() does not work when the CertExts size is 0
                // exts.decode(new ByteArrayInputStream(extensionsData));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return exts;
    }

    @Override
    public boolean setExtData(String key, CertificateSubjectName data) {
        if (data == null) {
            return false;
        }
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        try {
            data.encode(byteStream);
        } catch (IOException e) {
            return false;
        }
        return setExtData(key, byteStream.toByteArray());
    }

    @Override
    public CertificateSubjectName getExtDataInCertSubjectName(String key) {
        CertificateSubjectName name = null;
        byte[] nameData = getExtDataInByteArray(key);
        if (nameData != null) {
            try {
                // You must use DerInputStream
                // using ByteArrayInputStream fails
                name = new CertificateSubjectName(
                        new DerInputStream(nameData));
            } catch (IOException e) {
                return null;
            }
        }
        return name;
    }

    @Override
    public boolean setExtData(String key, String[] values) {
        if (values == null) {
            return false;
        }
        Hashtable<String, String> hashValue = new Hashtable<>();
        for (int index = 0; index < values.length; index++) {
            hashValue.put(Integer.toString(index), values[index]);
        }
        return setExtData(key, hashValue);
    }

    @Override
    public String[] getExtDataInStringArray(String key) {
        int index;

        Hashtable<String, String> hashValue = getExtDataInHashtable(key);
        if (hashValue == null) {
            String s = getExtDataInString(key);
            if (s == null) {
                return null;
            } else {
                String[] sa = { s };
                return sa;
            }
        }
        Set<String> arrayKeys = hashValue.keySet();
        Vector<Object> listValue = new Vector<>(arrayKeys.size());
        for (Iterator<String> iter = arrayKeys.iterator(); iter.hasNext();) {
            String arrayKey = iter.next();
            try {
                index = Integer.parseInt(arrayKey);
            } catch (NumberFormatException e) {
                return null;
            }
            if (listValue.size() < (index + 1)) {
                listValue.setSize(index + 1);
            }
            listValue.set(index,
                    hashValue.get(arrayKey));
        }
        return listValue.toArray(new String[0]);
    }

    @Override
    public IAttrSet asIAttrSet() {
        return new RequestIAttrSetWrapper(this);
    }

    @Override
    public String getRealm() {
        return realm;
    }

    @Override
    public void setRealm(String realm) {
        this.realm = realm;
    }
}
