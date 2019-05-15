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

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

@XmlRootElement
public class ACMEAuthorization {

    @XmlElement
    private String status;

    @XmlElement
    @JsonInclude(Include.NON_NULL)
    private String expires;

    @XmlElement
    private ACMEIdentifier identifier;

    @XmlElement
    private ACMEChallenge[] challenges;

    @XmlElement
    @JsonInclude(Include.NON_NULL)
    private Boolean wildcard;

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

    public ACMEIdentifier getIdentifier() {
        return identifier;
    }

    public void setIdentifier(ACMEIdentifier identifier) {
        this.identifier = identifier;
    }

    public ACMEChallenge[] getChallenges() {
        return challenges;
    }

    public void setChallenges(ACMEChallenge[] challenges) {
        this.challenges = challenges;
    }

    public Boolean getWildcard() {
        return wildcard;
    }

    public void setWildcard(Boolean wildcard) {
        this.wildcard = wildcard;
    }
}
