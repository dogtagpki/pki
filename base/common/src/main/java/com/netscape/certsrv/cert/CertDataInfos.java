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
package com.netscape.certsrv.cert;

import java.util.Collection;

import javax.xml.bind.annotation.XmlElementRef;
import javax.xml.bind.annotation.XmlRootElement;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.netscape.certsrv.base.DataCollection;
import com.netscape.certsrv.base.Link;

@XmlRootElement(name = "CertDataInfos")
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class CertDataInfos extends DataCollection<CertDataInfo> {

    @Override
    @XmlElementRef
    public Collection<CertDataInfo> getEntries() {
        return super.getEntries();
    }

    public Element toDOM(Document document) {

        Element infosElement = document.createElement("CertDataInfos");
        document.appendChild(infosElement);

        Element totalElement = document.createElement("total");
        totalElement.appendChild(document.createTextNode(Integer.toString(total)));
        infosElement.appendChild(totalElement);

        for (CertDataInfo certDataInfo : getEntries()) {
            Element infoElement = certDataInfo.toDOM(document);
            infosElement.appendChild(infoElement);
        }

        for (Link link : getLinks()) {
            Element infoElement = link.toDOM(document);
            infosElement.appendChild(infoElement);
        }

        return infosElement;
    }

    public static CertDataInfos fromDOM(Element infosElement) {

        CertDataInfos infos = new CertDataInfos();

        NodeList totalList = infosElement.getElementsByTagName("total");
        if (totalList.getLength() > 0) {
            String value = totalList.item(0).getTextContent();
            infos.setTotal(Integer.parseInt(value));
        }

        NodeList infoList = infosElement.getElementsByTagName("CertDataInfo");
        int infoCount = infoList.getLength();
        for (int i=0; i<infoCount; i++) {
           Element infoElement = (Element) infoList.item(i);
           CertDataInfo info = CertDataInfo.fromDOM(infoElement);
           infos.addEntry(info);
        }

        NodeList linkList = infosElement.getElementsByTagName("Link");
        int linkCount = linkList.getLength();
        for (int i=0; i<linkCount; i++) {
           Element linkElement = (Element) linkList.item(i);
           Link link = Link.fromDOM(linkElement);
           infos.addLink(link);
        }

        return infos;
    }
}
