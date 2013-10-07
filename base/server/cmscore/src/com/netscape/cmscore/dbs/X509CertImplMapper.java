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

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Set;
import java.util.Vector;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.security.extensions.NSCertTypeExtension;
import netscape.security.x509.BasicConstraintsExtension;
import netscape.security.x509.Extension;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509Key;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.AttributeNameHelper;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.EDBException;
import com.netscape.certsrv.dbs.IDBAttrMapper;
import com.netscape.certsrv.dbs.IDBObj;
import com.netscape.certsrv.dbs.certdb.ICertRecord;

/**
 * A class represents a mapper to serialize
 * x509 certificate into database.
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class X509CertImplMapper implements IDBAttrMapper {

    public X509CertImplMapper() {
    }

    public Enumeration<String> getSupportedLDAPAttributeNames() {
        Vector<String> v = new Vector<String>();

        v.addElement(CertDBSchema.LDAP_ATTR_NOT_BEFORE);
        v.addElement(CertDBSchema.LDAP_ATTR_NOT_AFTER);
        v.addElement(CertDBSchema.LDAP_ATTR_DURATION);
        v.addElement(CertDBSchema.LDAP_ATTR_EXTENSION);
        v.addElement(CertDBSchema.LDAP_ATTR_SUBJECT);
        v.addElement(CertDBSchema.LDAP_ATTR_SIGNED_CERT);
        v.addElement(CertDBSchema.LDAP_ATTR_VERSION);
        v.addElement(CertDBSchema.LDAP_ATTR_ALGORITHM);
        v.addElement(CertDBSchema.LDAP_ATTR_SIGNING_ALGORITHM);
        v.addElement(CertDBSchema.LDAP_ATTR_PUBLIC_KEY_DATA);
        return v.elements();
    }

    public void mapObjectToLDAPAttributeSet(IDBObj parent, String name,
            Object obj, LDAPAttributeSet attrs) throws EBaseException {
        if (obj == null) {
            throw new EBaseException(CMS.getUserMessage("CMS_DBS_SERIALIZE_FAILED", name));
        }
        try {
            X509CertImpl cert = (X509CertImpl) obj;
            // make information searchable
            Date notBefore = cert.getNotBefore();

            attrs.add(new LDAPAttribute(
                    CertDBSchema.LDAP_ATTR_NOT_BEFORE,
                    DateMapper.dateToDB(notBefore)));
            Date notAfter = cert.getNotAfter();

            attrs.add(new LDAPAttribute(CertDBSchema.LDAP_ATTR_NOT_AFTER,
                    DateMapper.dateToDB(notAfter)));
            attrs.add(new LDAPAttribute(CertDBSchema.LDAP_ATTR_DURATION,
                    DBSUtil.longToDB(notAfter.getTime() - notBefore.getTime())));
            attrs.add(new LDAPAttribute(CertDBSchema.LDAP_ATTR_SUBJECT,
                    cert.getSubjectDN().getName()));
            attrs.add(new LDAPAttribute(CertDBSchema.LDAP_ATTR_PUBLIC_KEY_DATA, cert.getPublicKey().getEncoded()));
            // make extension searchable
            Set<String> nonCritSet = cert.getNonCriticalExtensionOIDs();

            if (nonCritSet != null) {
                for (Iterator<String> i = nonCritSet.iterator(); i.hasNext();) {
                    String oid = i.next();

                    if (oid.equals("2.16.840.1.113730.1.1")) {
                        String extVal = getCertTypeExtensionInfo(cert);

                        if (extVal != null) {
                            oid = oid + ";" + extVal;
                        }
                    } else if (oid.equals("2.5.29.19")) {
                        String extVal = getBasicConstraintsExtensionInfo(cert);

                        if (extVal != null) {
                            oid = oid + ";" + extVal;
                        }
                    }
                    attrs.add(new LDAPAttribute(
                            CertDBSchema.LDAP_ATTR_EXTENSION, oid));
                }
            }
            Set<String> critSet = cert.getCriticalExtensionOIDs();

            if (critSet != null) {
                for (Iterator<String> i = critSet.iterator(); i.hasNext();) {
                    String oid = i.next();

                    if (oid.equals("2.16.840.1.113730.1.1")) {
                        String extVal = getCertTypeExtensionInfo(cert);

                        if (extVal != null) {
                            oid = oid + ";" + extVal;
                        }
                    } else if (oid.equals("2.5.29.19")) {
                        String extVal = getBasicConstraintsExtensionInfo(cert);

                        if (extVal != null) {
                            oid = oid + ";" + extVal;
                        }
                    }
                    attrs.add(new LDAPAttribute(
                            CertDBSchema.LDAP_ATTR_EXTENSION, oid));
                }
            }

            // something extra; so that we can rebuild the
            // object quickly
            // if we dont add ";binary", communicator does
            // not know how to display the certificate in
            // pretty print format.
            attrs.add(new LDAPAttribute(
                    CertDBSchema.LDAP_ATTR_SIGNED_CERT + ";binary",
                    cert.getEncoded()));

            attrs.add(new LDAPAttribute(
                    CertDBSchema.LDAP_ATTR_VERSION,
                    Integer.toString(cert.getVersion())));
            X509Key pubKey = (X509Key) cert.getPublicKey();

            attrs.add(new LDAPAttribute(
                    CertDBSchema.LDAP_ATTR_ALGORITHM,
                    pubKey.getAlgorithmId().getOID().toString()));
            attrs.add(new LDAPAttribute(
                    CertDBSchema.LDAP_ATTR_SIGNING_ALGORITHM,
                    cert.getSigAlgOID()));
        } catch (CertificateEncodingException e) {
            throw new EDBException(
                    CMS.getUserMessage("CMS_DBS_SERIALIZE_FAILED", name));
        }
    }

    private String getCertTypeExtensionInfo(X509CertImpl cert) {
        try {
            Extension ext = cert.getExtension("2.16.840.1.113730.1.1");

            if (ext == null) {
                // sometime time (during installation) it
                // is named differently
                ext = cert.getExtension(NSCertTypeExtension.NAME);
                if (ext == null)
                    return null;
            }
            NSCertTypeExtension nsExt = (NSCertTypeExtension) ext;

            String result = "";

            Boolean sslServer = (Boolean) nsExt.get(
                    NSCertTypeExtension.SSL_SERVER);

            result += "SSLServer=" + sslServer.toString() + ",";
            Boolean sslClient = (Boolean) nsExt.get(
                    NSCertTypeExtension.SSL_CLIENT);

            result += "SSLClient=" + sslClient.toString() + ",";
            Boolean email = (Boolean) nsExt.get(
                    NSCertTypeExtension.EMAIL);

            result += "Email=" + email.toString() + ",";
            Boolean sslCA = (Boolean) nsExt.get(
                    NSCertTypeExtension.SSL_CA);

            result += "SSLCA=" + sslCA.toString() + ",";
            Boolean mailCA = (Boolean) nsExt.get(
                    NSCertTypeExtension.EMAIL_CA);

            result += "EmailCA=" + mailCA.toString() + ",";
            Boolean objectSigning = (Boolean) nsExt.get(
                    NSCertTypeExtension.OBJECT_SIGNING);

            result += "objectSigning=" +
                    objectSigning.toString();
            return result;
        } catch (Exception e) {
            return null;
        }
    }

    private String getBasicConstraintsExtensionInfo(X509CertImpl cert) {
        try {
            Extension ext = cert.getExtension("2.5.29.19");

            if (ext == null) {
                // sometime time (during installation) it
                // is named differently
                ext = cert.getExtension(BasicConstraintsExtension.NAME);
                if (ext == null)
                    return null;
            }
            BasicConstraintsExtension bcExt = (BasicConstraintsExtension) ext;

            String result = "";

            Boolean isCA = (Boolean) bcExt.get(
                    BasicConstraintsExtension.IS_CA);

            result += "isCA=" + isCA.toString() + ",";
            Integer pathLen = (Integer) bcExt.get(
                    BasicConstraintsExtension.PATH_LEN);

            result += "pathLen=" + pathLen.toString();
            return result;
        } catch (Exception e) {
            return null;
        }
    }

    public void mapLDAPAttributeSetToObject(LDAPAttributeSet attrs,
            String name, IDBObj parent) throws EBaseException {
        try {
            // rebuild object quickly using binary image
            // XXX bad! when we add this attribute,
            // we add it as userCertificate, but when
            // we retrieve it, DS returns it as
            // userCertificate;binary. So I cannot do the
            // following:
            //      LDAPAttribute attr = attrs.getAttribute(
            //  	  Schema.LDAP_ATTR_SIGNED_CERT);

            LDAPAttribute attr = attrs.getAttribute(
                    CertDBSchema.LDAP_ATTR_SIGNED_CERT);

            if (attr == null) {
                // YUK!
                attr = attrs.getAttribute(
                            CertDBSchema.LDAP_ATTR_SIGNED_CERT + ";binary");
            }
            if (attr != null) {
                byte der[] = (byte[])
                        attr.getByteValues().nextElement();
                X509CertImpl impl = new X509CertImpl(der);

                parent.set(name, impl);
            }
        } catch (CertificateException e) {
            //throw new EDBException(
            //	DBResources.FAILED_TO_DESERIALIZE_1, name);
            parent.set(name, null);
        } catch (Exception e) {
            //throw new EDBException(
            //	DBResources.FAILED_TO_DESERIALIZE_1, name);
            parent.set(name, null);

        }
    }

    public String mapSearchFilter(String name, String op, String value)
            throws EBaseException {
        AttributeNameHelper h = new AttributeNameHelper(name);
        String suffix = h.getSuffix();

        if (suffix.equalsIgnoreCase(ICertRecord.X509CERT_NOT_BEFORE)) {
            name = CertDBSchema.LDAP_ATTR_NOT_BEFORE;
            try {
                value = DateMapper.dateToDB(new
                            Date(Long.parseLong(value)));
            } catch (NumberFormatException e) {
            }
        } else if (suffix.equalsIgnoreCase(ICertRecord.X509CERT_NOT_AFTER)) {
            name = CertDBSchema.LDAP_ATTR_NOT_AFTER;
            try {
                value = DateMapper.dateToDB(new
                            Date(Long.parseLong(value)));
            } catch (NumberFormatException e) {
            }
        } else if (suffix.equalsIgnoreCase(ICertRecord.X509CERT_SUBJECT)) {
            name = CertDBSchema.LDAP_ATTR_SUBJECT;
        } else if (suffix.equalsIgnoreCase(ICertRecord.X509CERT_PUBLIC_KEY_DATA)) {
            name = CertDBSchema.LDAP_ATTR_PUBLIC_KEY_DATA;
        } else if (suffix.equalsIgnoreCase(ICertRecord.X509CERT_DURATION)) {
            name = CertDBSchema.LDAP_ATTR_DURATION;
            value = DBSUtil.longToDB(Long.parseLong(value));
        } else if (suffix.equalsIgnoreCase(ICertRecord.X509CERT_VERSION)) {
            name = CertDBSchema.LDAP_ATTR_VERSION;
        } else if (suffix.equalsIgnoreCase(ICertRecord.X509CERT_ALGORITHM)) {
            name = CertDBSchema.LDAP_ATTR_ALGORITHM;
        } else if (suffix.equalsIgnoreCase(ICertRecord.X509CERT_SIGNING_ALGORITHM)) {
            name = CertDBSchema.LDAP_ATTR_SIGNING_ALGORITHM;
        } else if (suffix.equalsIgnoreCase(ICertRecord.X509CERT_SERIAL_NUMBER)) {
            name = CertDBSchema.LDAP_ATTR_CERT_RECORD_ID;
        } else if (suffix.equalsIgnoreCase(ICertRecord.X509CERT_EXTENSION)) {
            name = CertDBSchema.LDAP_ATTR_EXTENSION;
        } else if (suffix.equalsIgnoreCase(ICertRecord.ATTR_REVO_INFO)) {
            name = CertDBSchema.LDAP_ATTR_REVO_INFO;
            value = "*;CRLReasonExtension=" + value;
        } else if (suffix.equalsIgnoreCase("nsExtension.SSLClient")) {
            // special case for NS cert type extension
            name = CertDBSchema.LDAP_ATTR_EXTENSION;
            if (value.equals("on")) {
                value = "2.16.840.1.113730.1.1;*SSLClient=true*";
            } else {
                value = "2.16.840.1.113730.1.1;*SSLClient=false*";
            }
        } else if (suffix.equalsIgnoreCase("nsExtension.SSLServer")) {
            // special case for NS cert type extension
            name = CertDBSchema.LDAP_ATTR_EXTENSION;
            if (value.equals("on")) {
                value = "2.16.840.1.113730.1.1;*SSLServer=true*";
            } else {
                value = "2.16.840.1.113730.1.1;*SSLServer=false*";
            }
        } else if (suffix.equalsIgnoreCase("nsExtension.SecureEmail")) {
            // special case for NS cert type extension
            name = CertDBSchema.LDAP_ATTR_EXTENSION;
            if (value.equals("on")) {
                value = "2.16.840.1.113730.1.1;*Email=true*";
            } else {
                value = "2.16.840.1.113730.1.1;*Email=false*";
            }
        } else if (suffix.equalsIgnoreCase("nsExtension.SubordinateSSLCA")) {
            // special case for NS cert type extension
            name = CertDBSchema.LDAP_ATTR_EXTENSION;
            if (value.equals("on")) {
                value = "2.16.840.1.113730.1.1;*SSLCA=true*";
            } else {
                value = "2.16.840.1.113730.1.1;*SSLCA=false*";
            }
        } else if (suffix.equalsIgnoreCase("nsExtension.SubordinateEmailCA")) {
            // special case for NS cert type extension
            name = CertDBSchema.LDAP_ATTR_EXTENSION;
            if (value.equals("on")) {
                value = "2.16.840.1.113730.1.1;*EmailCA=true*";
            } else {
                value = "2.16.840.1.113730.1.1;*EmailCA=false*";
            }
        } else if (suffix.equalsIgnoreCase("BasicConstraints.isCA")) {
            // special case for Basic Constraints extension
            name = CertDBSchema.LDAP_ATTR_EXTENSION;
            if (value.equals("on")) {
                value = "2.5.29.19;*isCA=true*";
            } else {
                value = "2.5.29.19;*isCA=false*";
            }
        }
        return name + op + value;
    }
}
