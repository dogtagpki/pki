package com.netscape.cmscore.request;

import java.math.BigInteger;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;
import java.util.Vector;

import org.dogtagpki.server.authentication.AuthToken;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.CertificateSubjectName;
import org.mozilla.jss.netscape.security.x509.RevokedCertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.base.IAttrSet;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;

/**
 * Default testing stub for the Request class.
 */
public class RequestDefaultStub extends Request {

    public RequestDefaultStub() {
        super(null);
    }

    @Override
    public RequestId getRequestId() {
        return null;
    }

    @Override
    public RequestStatus getRequestStatus() {
        return null;
    }

    @Override
    public String getSourceId() {
        return null;
    }

    @Override
    public void setSourceId(String id) {
    }

    @Override
    public String getRequestOwner() {
        return null;
    }

    @Override
    public void setRequestOwner(String owner) {
    }

    @Override
    public String getRequestType() {
        return null;
    }

    @Override
    public void setRequestType(String type) {
    }

    @Override
    public String getRequestVersion() {
        return null;
    }

    @Override
    public Date getCreationTime() {
        return null;
    }

    @Override
    public void setCreationTime(Date date) {
    }

    @Override
    public Date getModificationTime() {
        return null;
    }

    @Override
    public void setModificationTime(Date date) {
    }

    public void set(String type, Object value) {
    }

    public Object get(String type) {
        return null;
    }

    public Enumeration<String> getAttrNames() {
        return null;
    }

    @Override
    public void deleteExtData(String type) {
    }

    @Override
    public void copyContents(Request req) {
    }

    @Override
    public String getContext() {
        return null;
    }

    @Override
    public void setContext(String ctx) {
    }

    @Override
    public void setRequestStatus(RequestStatus s) {
    }

    @Override
    public boolean isSuccess() {
        return false;
    }

    @Override
    public String getError(Locale locale) {
        return null;
    }

    @Override
    public String getErrorCode(Locale locale) {
        return null;
    }

    @Override
    public boolean setExtData(String key, String value) {
        return false;
    }

    @Override
    public boolean setExtData(String key, Hashtable<String, String> value) {
        return false;
    }

    @Override
    public boolean isSimpleExtDataValue(String key) {
        return false;
    }

    @Override
    public String getExtDataInString(String key) {
        return null;
    }

    @Override
    public Hashtable<String, String> getExtDataInHashtable(String key) {
        return null;
    }

    @Override
    public Enumeration<String> getExtDataKeys() {
        return null;
    }

    @Override
    public boolean setExtData(String key, String[] values) {
        return false;
    }

    @Override
    public String[] getExtDataInStringArray(String key) {
        return new String[0];
    }

    @Override
    public boolean setExtData(String key, String subkey, String value) {
        return false;
    }

    @Override
    public String getExtDataInString(String key, String subkey) {
        return null;
    }

    @Override
    public boolean setExtData(String key, Integer value) {
        return false;
    }

    @Override
    public Integer getExtDataInInteger(String key) {
        return null;
    }

    @Override
    public boolean setExtData(String key, Integer[] values) {
        return false;
    }

    @Override
    public Integer[] getExtDataInIntegerArray(String key) {
        return new Integer[0];
    }

    @Override
    public boolean setExtData(String key, BigInteger value) {
        return false;
    }

    @Override
    public BigInteger getExtDataInBigInteger(String key) {
        return null;
    }

    @Override
    public boolean setExtData(String key, BigInteger[] values) {
        return false;
    }

    @Override
    public BigInteger[] getExtDataInBigIntegerArray(String key) {
        return new BigInteger[0];
    }

    @Override
    public boolean setExtData(String key, Throwable e) {
        return false;
    }

    @Override
    public boolean setExtData(String key, byte[] data) {
        return false;
    }

    @Override
    public byte[] getExtDataInByteArray(String key) {
        return new byte[0];
    }

    @Override
    public boolean setExtData(String key, X509CertImpl data) {
        return false;
    }

    @Override
    public X509CertImpl getExtDataInCert(String key) {
        return null;
    }

    @Override
    public boolean setExtData(String key, X509CertImpl[] data) {
        return false;
    }

    @Override
    public X509CertImpl[] getExtDataInCertArray(String key) {
        return new X509CertImpl[0];
    }

    @Override
    public boolean setExtData(String key, X509CertInfo data) {
        return false;
    }

    @Override
    public X509CertInfo getExtDataInCertInfo(String key) {
        return null;
    }

    @Override
    public boolean setExtData(String key, X509CertInfo[] data) {
        return false;
    }

    @Override
    public X509CertInfo[] getExtDataInCertInfoArray(String key) {
        return new X509CertInfo[0];
    }

    @Override
    public boolean setExtData(String key, RevokedCertImpl[] data) {
        return false;
    }

    @Override
    public RevokedCertImpl[] getExtDataInRevokedCertArray(String key) {
        return new RevokedCertImpl[0];
    }

    @Override
    public boolean setExtData(String key, Vector<?> data) {
        return false;
    }

    @Override
    public Vector<String> getExtDataInStringVector(String key) {
        return null;
    }

    @Override
    public boolean getExtDataInBoolean(String type, boolean defVal) {
        return false;
    }

    @Override
    public boolean getExtDataInBoolean(String prefix, String type, boolean defVal) {
        return false;
    }

    @Override
    public boolean setExtData(String key, AuthToken data) {
        return false;
    }

    @Override
    public AuthToken getExtDataInAuthToken(String key) {
        return null;
    }

    @Override
    public boolean setExtData(String key, CertificateExtensions data) {
        return false;
    }

    @Override
    public CertificateExtensions getExtDataInCertExts(String key) {
        return null;
    }

    @Override
    public boolean setExtData(String key, CertificateSubjectName data) {
        return false;
    }

    @Override
    public CertificateSubjectName getExtDataInCertSubjectName(String key) {
        return null;
    }

    @Override
    public IAttrSet asIAttrSet() {
        return null;
    }

    @Override
    public String getRealm() {
        return null;
    }

    @Override
    public void setRealm(String realm) {
    }
}
