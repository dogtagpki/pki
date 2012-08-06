//--- BEGIN COPYRIGHT BLOCK ---
//This program is free software; you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; version 2 of the License.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License along
//with this program; if not, write to the Free Software Foundation, Inc.,
//51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
//(C) 2012 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---
package com.netscape.cms.servlet.cert.model;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.xml.bind.annotation.XmlElementRef;
import javax.xml.bind.annotation.XmlRootElement;

import org.jboss.resteasy.plugins.providers.atom.Link;

@XmlRootElement(name = "CertDataInfos")
public class CertDataInfos {

    protected Collection<CertDataInfo> certInfos = new ArrayList<CertDataInfo>();
    protected List<Link> links = new ArrayList<Link>();

    /**
     * @return the CertInfos
     */
    @XmlElementRef
    public Collection<CertDataInfo> getCertInfos() {
        return certInfos;
    }

    /**
     * @param certInfos the CertInfos to set
     */
    public void setCertInfos(Collection<CertDataInfo> certInfos) {
        this.certInfos = certInfos;
    }

    /**
     * @return the links
     */
    @XmlElementRef
    public List<Link> getLinks() {
        return links;
    }

    /**
     * @param links the links to set
     */
    public void setLinks(List<Link> links) {
        this.links = links;
    }

    public void addCertData(CertDataInfo certInfo){
        this.certInfos.add(certInfo);
    }

    public void addLink(Link link) {
        this.links.add(link);
    }
}
