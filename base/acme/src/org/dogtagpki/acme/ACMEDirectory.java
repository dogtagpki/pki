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
public class ACMEDirectory {

    @XmlElement
    private URI newNonce;

    @XmlElement
    private URI newAccount;

    @XmlElement
    private URI newOrder;

    @XmlElement
    private URI newAuthz;

    @XmlElement
    private URI revokeCert;

    @XmlElement
    private URI keyChange;

    @XmlElement
    @JsonInclude(Include.NON_NULL)
    private ACMEMetadata meta;

    public URI getNewNonce() {
        return newNonce;
    }

    public void setNewNonce(URI newNonce) {
        this.newNonce = newNonce;
    }

    public URI getNewAccount() {
        return newAccount;
    }

    public void setNewAccount(URI newAccount) {
        this.newAccount = newAccount;
    }

    public URI getNewOrder() {
        return newOrder;
    }

    public void setNewOrder(URI newOrder) {
        this.newOrder = newOrder;
    }

    public URI getNewAuthz() {
        return newAuthz;
    }

    public void setNewAuthz(URI newAuthz) {
        this.newAuthz = newAuthz;
    }

    public URI getRevokeCert() {
        return revokeCert;
    }

    public void setRevokeCert(URI revokeCert) {
        this.revokeCert = revokeCert;
    }

    public URI getKeyChange() {
        return keyChange;
    }

    public void setKeyChange(URI keyChange) {
        this.keyChange = keyChange;
    }

    public ACMEMetadata getMeta() {
        return meta;
    }

    public void setMeta(ACMEMetadata meta) {
        this.meta = meta;
    }
}
