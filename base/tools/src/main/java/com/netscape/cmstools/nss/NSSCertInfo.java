//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.nss;

import java.util.Date;
import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.util.JSONSerializer;

@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class NSSCertInfo implements JSONSerializer {

    String nickname;
    CertId serialNumber;
    String subjectDN;
    String issuerDN;
    Date notBefore;
    Date notAfter;
    String trustFlags;

    @JsonProperty
    public String getNickname() {
        return nickname;
    }

    public void setNickname(String nickname) {
        this.nickname = nickname;
    }

    @JsonProperty
    public CertId getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(CertId serialNumber) {
        this.serialNumber = serialNumber;
    }

    @JsonProperty
    public String getSubjectDN() {
        return subjectDN;
    }

    public void setSubjectDN(String subjectDN) {
        this.subjectDN = subjectDN;
    }

    @JsonProperty
    public String getIssuerDN() {
        return issuerDN;
    }

    public void setIssuerDN(String issuerDN) {
        this.issuerDN = issuerDN;
    }

    @JsonProperty
    public Date getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(Date notBefore) {
        this.notBefore = notBefore;
    }

    @JsonProperty
    public Date getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(Date notAfter) {
        this.notAfter = notAfter;
    }

    @JsonProperty
    public String getTrustFlags() {
        return trustFlags;
    }

    public void setTrustFlags(String type) {
        this.trustFlags = type;
    }

    @Override
    public int hashCode() {
        return Objects.hash(issuerDN, nickname, notAfter, notBefore, serialNumber, subjectDN, trustFlags);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        NSSCertInfo other = (NSSCertInfo) obj;
        return Objects.equals(issuerDN, other.issuerDN) && Objects.equals(nickname, other.nickname)
                && Objects.equals(notAfter, other.notAfter) && Objects.equals(notBefore, other.notBefore)
                && Objects.equals(serialNumber, other.serialNumber) && Objects.equals(subjectDN, other.subjectDN)
                && Objects.equals(trustFlags, other.trustFlags);
    }
}
