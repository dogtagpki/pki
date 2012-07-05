package com.netscape.cmscore.request;

import java.math.BigInteger;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;
import java.util.Vector;

import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateSubjectName;
import netscape.security.x509.RevokedCertImpl;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.IAttrSet;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;

/**
 * Default testing stub for the IRequest interface.
 */
public class RequestDefaultStub implements IRequest {
    private static final long serialVersionUID = -8466522941927034614L;

    public RequestId getRequestId() {
        return null;
    }

    public RequestStatus getRequestStatus() {
        return null;
    }

    public String getSourceId() {
        return null;
    }

    public void setSourceId(String id) {
    }

    public String getRequestOwner() {
        return null;
    }

    public void setRequestOwner(String owner) {
    }

    public String getRequestType() {
        return null;
    }

    public void setRequestType(String type) {
    }

    public String getRequestVersion() {
        return null;
    }

    public Date getCreationTime() {
        return null;
    }

    public Date getModificationTime() {
        return null;
    }

    public void set(String type, Object value) {
    }

    public Object get(String type) {
        return null;
    }

    public Enumeration<String> getAttrNames() {
        return null;
    }

    public void deleteExtData(String type) {
    }

    public void copyContents(IRequest req) {
    }

    public String getContext() {
        return null;
    }

    public void setContext(String ctx) {
    }

    public void setRequestStatus(RequestStatus s) {
    }

    public boolean isSuccess() {
        return false;
    }

    public String getError(Locale locale) {
        return null;
    }

    public boolean setExtData(String key, String value) {
        return false;
    }

    public boolean setExtData(String key, Hashtable<String, String> value) {
        return false;
    }

    public boolean isSimpleExtDataValue(String key) {
        return false;
    }

    public String getExtDataInString(String key) {
        return null;
    }

    public Hashtable<String, String> getExtDataInHashtable(String key) {
        return null;
    }

    public Enumeration<String> getExtDataKeys() {
        return null;
    }

    public boolean setExtData(String key, String[] values) {
        return false;
    }

    public String[] getExtDataInStringArray(String key) {
        return new String[0];
    }

    public boolean setExtData(String key, String subkey, String value) {
        return false;
    }

    public String getExtDataInString(String key, String subkey) {
        return null;
    }

    public boolean setExtData(String key, Integer value) {
        return false;
    }

    public Integer getExtDataInInteger(String key) {
        return null;
    }

    public boolean setExtData(String key, Integer[] values) {
        return false;
    }

    public Integer[] getExtDataInIntegerArray(String key) {
        return new Integer[0];
    }

    public boolean setExtData(String key, BigInteger value) {
        return false;
    }

    public BigInteger getExtDataInBigInteger(String key) {
        return null;
    }

    public boolean setExtData(String key, BigInteger[] values) {
        return false;
    }

    public BigInteger[] getExtDataInBigIntegerArray(String key) {
        return new BigInteger[0];
    }

    public boolean setExtData(String key, Throwable e) {
        return false;
    }

    public boolean setExtData(String key, byte[] data) {
        return false;
    }

    public byte[] getExtDataInByteArray(String key) {
        return new byte[0];
    }

    public boolean setExtData(String key, X509CertImpl data) {
        return false;
    }

    public X509CertImpl getExtDataInCert(String key) {
        return null;
    }

    public boolean setExtData(String key, X509CertImpl[] data) {
        return false;
    }

    public X509CertImpl[] getExtDataInCertArray(String key) {
        return new X509CertImpl[0];
    }

    public boolean setExtData(String key, X509CertInfo data) {
        return false;
    }

    public X509CertInfo getExtDataInCertInfo(String key) {
        return null;
    }

    public boolean setExtData(String key, X509CertInfo[] data) {
        return false;
    }

    public X509CertInfo[] getExtDataInCertInfoArray(String key) {
        return new X509CertInfo[0];
    }

    public boolean setExtData(String key, RevokedCertImpl[] data) {
        return false;
    }

    public RevokedCertImpl[] getExtDataInRevokedCertArray(String key) {
        return new RevokedCertImpl[0];
    }

    public boolean setExtData(String key, Vector<?> data) {
        return false;
    }

    public Vector<String> getExtDataInStringVector(String key) {
        return null;
    }

    public boolean getExtDataInBoolean(String type, boolean defVal) {
        return false;
    }

    public boolean getExtDataInBoolean(String prefix, String type, boolean defVal) {
        return false;
    }

    public boolean setExtData(String key, IAuthToken data) {
        return false;
    }

    public IAuthToken getExtDataInAuthToken(String key) {
        return null;
    }

    public boolean setExtData(String key, CertificateExtensions data) {
        return false;
    }

    public CertificateExtensions getExtDataInCertExts(String key) {
        return null;
    }

    public boolean setExtData(String key, CertificateSubjectName data) {
        return false;
    }

    public CertificateSubjectName getExtDataInCertSubjectName(String key) {
        return null;
    }

    public IAttrSet asIAttrSet() {
        return null;
    }
}
