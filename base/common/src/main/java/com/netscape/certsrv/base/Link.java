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
// (C) 2011 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---/**
package com.netscape.certsrv.base;

import java.net.URI;
import java.util.Objects;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

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
public class Link implements JSONSerializer {
    private String relationship;
    private String href;
    private String type;

    public Link() {
        // required for jaxb
    }

    public Link(String relationship, String href, String type) {
        this.relationship = relationship;
        this.href = href;
        this.type = type;
    }

    public Link(String relationship, URI uri) {
        this.relationship = relationship;
        this.href = uri.toString();
    }

    /**
     * @return the relationship
     */
    public String getRelationship() {
        return relationship;
    }

    /**
     * @param relationship the relationship to set
     */
    public void setRelationship(String relationship) {
        this.relationship = relationship;
    }

    /**
     * @return the href
     */
    public String getHref() {
        return href;
    }

    /**
     * @param href the href to set
     */
    public void setHref(String href) {
        this.href = href;
    }

    /**
     * @return the type
     */
    public String getType() {
        return type;
    }

    /**
     * @param type the type to set
     */
    public void setType(String type) {
        this.type = type;
    }

    @Override
    public int hashCode() {
        return Objects.hash(href, relationship, type);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        Link other = (Link) obj;
        return Objects.equals(href, other.href) &&
                Objects.equals(relationship, other.relationship) &&
                Objects.equals(type, other.type);
    }

    public Element toDOM(Document document) {

        Element linkElement = document.createElement("Link");

        if (relationship != null) {
            Element relationshipElement = document.createElement("relationship");
            relationshipElement.appendChild(document.createTextNode(relationship));
            linkElement.appendChild(relationshipElement);
        }

        if (href != null) {
            Element hrefElement = document.createElement("href");
            hrefElement.appendChild(document.createTextNode(href));
            linkElement.appendChild(hrefElement);
        }

        if (type != null) {
            Element typeElement = document.createElement("type");
            typeElement.appendChild(document.createTextNode(type));
            linkElement.appendChild(typeElement);
        }

        return linkElement;
    }

    public static Link fromDOM(Element linkElement) {

        Link link = new Link();

        NodeList relationshipList = linkElement.getElementsByTagName("relationship");
        if (relationshipList.getLength() > 0) {
            String value = relationshipList.item(0).getTextContent();
            link.setRelationship(value);
        }

        NodeList hrefList = linkElement.getElementsByTagName("href");
        if (hrefList.getLength() > 0) {
            String value = hrefList.item(0).getTextContent();
            link.setHref(value);
        }

        NodeList typeList = linkElement.getElementsByTagName("type");
        if (typeList.getLength() > 0) {
            String value = typeList.item(0).getTextContent();
            link.setType(value);
        }

        return link;
    }
}
