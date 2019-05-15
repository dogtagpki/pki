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
package org.dogtagpki.acme;

import java.net.URI;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

@XmlRootElement
public class ACMEOrder {

    @XmlElement
    private String status;

    @XmlElement
    private String expires;

    @XmlElement
    private ACMEIdentifier[] identifiers;

    @XmlElement
    private String notBefore;

    @XmlElement
    private String notAfter;

    @XmlElement
    @JsonInclude(Include.NON_NULL)
    private String error;

    @XmlElement
    private URI[] authorizations;

    @XmlElement
    private URI finalize;

    @XmlElement
    @JsonInclude(Include.NON_NULL)
    private String csr;

    @XmlElement
    @JsonInclude(Include.NON_NULL)
    private URI certificate;

    @XmlElement
    @JsonInclude(Include.NON_NULL)
    private URI resource;

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getExpires() {
        return expires;
    }

    public void setExpires(String expires) {
        this.expires = expires;
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

    public ACMEIdentifier[] getIdentifiers() {
        return identifiers;
    }

    public void setIdentifiers(ACMEIdentifier[] identifiers) {
        this.identifiers = identifiers;
    }

    public URI[] getAuthorizations() {
        return authorizations;
    }

    public void setAuthorizations(URI[] authorizations) {
        this.authorizations = authorizations;
    }

    public URI getFinalize() {
        return finalize;
    }

    public void setFinalize(URI finalize) {
        this.finalize = finalize;
    }

    public String getCSR() {
        return csr;
    }

    public void setCSR(String csr) {
        this.csr = csr;
    }

    public URI getCertificate() {
        return certificate;
    }

    public void setCertificate(URI certificate) {
        this.certificate = certificate;
    }

    public URI getResource() {
        return resource;
    }

    public void setResource(URI resource) {
        this.resource = resource;
    }
}
