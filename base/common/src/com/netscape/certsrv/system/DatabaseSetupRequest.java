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

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * @author alee
 *
 */
@XmlRootElement(name="DatabaseSetupRequest")
@XmlAccessorType(XmlAccessType.FIELD)
public class DatabaseSetupRequest {

    @XmlElement
    protected String pin;

    @XmlElement(defaultValue="false")
    protected String isClone;

    public DatabaseSetupRequest() {
        // required for JAXB
    }

    public String getPin() {
        return pin;
    }

    public void setPin(String pin) {
        this.pin = pin;
    }

    public boolean isClone() {
        return (isClone!= null) && isClone.equalsIgnoreCase("true");
    }

    public void setClone(String isClone) {
        this.isClone = isClone;
    }

    @Override
    public String toString() {
        return "DatabaseSetupRequest [pin=XXXX" +
               ", isClone=" + isClone +
               "]";
    }
}
