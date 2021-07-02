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
// (C) 2019 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.system;

import java.net.URL;
import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author alee
 *
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class CertificateSetupRequest implements JSONSerializer {

    protected String pin;

    protected InstallToken installToken;

    protected String tag;

    protected SystemCertData systemCert;

    protected Boolean clone;

    protected URL masterURL;

    public CertificateSetupRequest() {
        // required for JAXB
    }

    public String getPin() {
        return pin;
    }

    public void setPin(String pin) {
        this.pin = pin;
    }

    public InstallToken getInstallToken() {
        return installToken;
    }

    public void setInstallToken(InstallToken installToken) {
        this.installToken = installToken;
    }

    public String getTag() {
        return tag;
    }

    public void setTag(String tag) {
        this.tag = tag;
    }

   public SystemCertData getSystemCert() {
       return systemCert;
   }

   public void setSystemCert(SystemCertData systemCert) {
       this.systemCert = systemCert;
   }

    public Boolean isClone() {
        return clone;
    }

    public void setClone(Boolean clone) {
        this.clone = clone;
    }

    public URL getMasterURL() {
        return masterURL;
    }

    public void setMasterURL(URL masterURL) {
        this.masterURL = masterURL;
    }

    @Override
    public String toString() {
        return "CertificateSetupRequest [pin=XXXX" +
               ", tag=" + tag +
               ", systemCert=" + systemCert +
               ", clone=" + clone +
               ", masterURL=" + masterURL +
               "]";
    }

    @Override
    public int hashCode() {
        return Objects.hash(clone, installToken, masterURL, pin, systemCert, tag);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        CertificateSetupRequest other = (CertificateSetupRequest) obj;
        return Objects.equals(clone, other.clone) && Objects.equals(installToken, other.installToken)
                && Objects.equals(masterURL, other.masterURL) && Objects.equals(pin, other.pin)
                && Objects.equals(systemCert, other.systemCert) && Objects.equals(tag, other.tag);
    }

}
