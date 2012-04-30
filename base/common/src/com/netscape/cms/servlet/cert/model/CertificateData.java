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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.servlet.cert.model;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.dbs.certdb.CertIdAdapter;

/**
 * @author alee
 *
 */
@XmlRootElement(name = "CertificateData")
@XmlAccessorType(XmlAccessType.FIELD)
public class CertificateData {
    @XmlElement
    private String b64;

    @XmlElement
    private String prettyPrint;

    @XmlElement
    private String subjectName;

    @XmlElement
    private String pkcs7CertChain;

    @XmlElement
    @XmlJavaTypeAdapter(CertIdAdapter.class)
    private CertId serialNo;

    @XmlElement
    private String notBefore;

    @XmlElement
    private String notAfter;

    @XmlElement
    private String issuerName;

    public CertificateData() {
        // required for jaxb
    }

    /**
     * @return the b64
     */
    public String getB64() {
        return b64;
    }

    /**
     * @param b64 the b64 to set
     */
    public void setB64(String b64) {
        this.b64 = b64;
    }

    public String getPrettyPrint() {
        return prettyPrint;
    }

    public void setPrettyPrint(String prettyPrint) {
        this.prettyPrint = prettyPrint;
    }

    public void setPkcs7CertChain(String chain) {
        this.pkcs7CertChain = chain;
    }

    public String getPkcs7CertChain() {
        return pkcs7CertChain;
    }

    public String getSubjectName() {
        return subjectName;
    }

    public void setSubjectName(String subjectName) {
        this.subjectName = subjectName;
    }

    public CertId getSerialNo() {
        return serialNo;
    }

    public void setSerialNo(CertId serialNo) {
        this.serialNo = serialNo;
    }

    public String getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(String notBefore) {
        this.notBefore = notBefore;
    }

    public String getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(String notAfter) {
        this.notAfter = notAfter;
    }

    public String getIssuerName() {
        return issuerName;
    }

    public void setIssuerName(String issuerName) {
        this.issuerName = issuerName;
    }

}
