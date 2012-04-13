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
package com.netscape.cms.servlet.csadmin.model;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * @author alee
 *
 */
@XmlRootElement(name="DomainInfo")
public class DomainInfo {
    
    @XmlElement(name="CAList")
    protected SecurityDomainHostList caList;
    
    @XmlElement(name="KRAList")
    protected SecurityDomainHostList kraList;
    
    @XmlElement(name="OCSPList")
    protected SecurityDomainHostList ocspList;
    
    @XmlElement(name="TKSList")
    protected SecurityDomainHostList tksList;
    
    @XmlElement(name="TPSList")
    protected SecurityDomainHostList tpsList;
    
    @XmlElement(name="RAList")
    protected SecurityDomainHostList raList;
    
    @XmlElement
    protected String name;

    /**
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * @param name the name to set
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * @return the caList
     */
    public SecurityDomainHostList getCaList() {
        return caList;
    }

    /**
     * @param caList the caList to set
     */
    public void setCaList(SecurityDomainHostList caList) {
        this.caList = caList;
    }

    /**
     * @return the kraList
     */
    public SecurityDomainHostList getKraList() {
        return kraList;
    }

    /**
     * @param kraList the kraList to set
     */
    public void setKraList(SecurityDomainHostList kraList) {
        this.kraList = kraList;
    }

    /**
     * @return the ocspList
     */
    public SecurityDomainHostList getOcspList() {
        return ocspList;
    }

    /**
     * @param ocspList the ocspList to set
     */
    public void setOcspList(SecurityDomainHostList ocspList) {
        this.ocspList = ocspList;
    }

    /**
     * @return the tksList
     */
    public SecurityDomainHostList getTksList() {
        return tksList;
    }

    /**
     * @param tksList the tksList to set
     */
    public void setTksList(SecurityDomainHostList tksList) {
        this.tksList = tksList;
    }

    /**
     * @return the tpsList
     */
    public SecurityDomainHostList getTpsList() {
        return tpsList;
    }

    /**
     * @param tpsList the tpsList to set
     */
    public void setTpsList(SecurityDomainHostList tpsList) {
        this.tpsList = tpsList;
    }

    /**
     * @return the raList
     */
    public SecurityDomainHostList getRaList() {
        return raList;
    }

    /**
     * @param raList the raList to set
     */
    public void setRaList(SecurityDomainHostList raList) {
        this.raList = raList;
    }

     
    
    
    
     

}
