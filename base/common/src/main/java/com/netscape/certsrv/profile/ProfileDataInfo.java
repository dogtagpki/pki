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
//(C) 2011 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---

package com.netscape.certsrv.profile;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.Objects;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

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
public class ProfileDataInfo implements JSONSerializer {

    protected String profileURL;

    protected String profileId;

    protected String profileName;

    protected String profileDescription;

    protected Boolean profileVisible;

    protected Boolean profileEnable;

    protected String profileEnableBy;

    public ProfileDataInfo() {
    }

    /**
     * @return the profileURL
     */
    public String getProfileURL() {
        return profileURL;
    }

    /**
     * @param profileURL the profileURL to set
     */
    public void setProfileURL(String profileURL) {
        this.profileURL = profileURL;
    }

    public void setProfileId(String profileId) {
        this.profileId = profileId;
    }

    /**
     * @return the profile ID in the profileURL
     */
    public String getProfileId() {
        return profileId;
    }

    public String getProfileName() {
        return profileName;
    }

    public void setProfileName(String profileName) {
        this.profileName = profileName;
    }

    public String getProfileDescription() {
        return profileDescription;
    }

    public void setProfileDescription(String profileDescription) {
        this.profileDescription = profileDescription;
    }


    public Boolean getProfileVisible() {
        return profileVisible;
    }

    public void setProfileVisible(Boolean profileVisible) {
        this.profileVisible = profileVisible;
    }

    public Boolean getProfileEnable() {
        return profileEnable;
    }

    public void setProfileEnable(Boolean profileEnable) {
        this.profileEnable = profileEnable;
    }

    public String getProfileEnableBy() {
        return profileEnableBy;
    }

    public void setProfileEnableBy(String profileEnableBy) {
        this.profileEnableBy = profileEnableBy;
    }

    @Override
    public int hashCode() {
        return Objects.hash(profileDescription, profileId, profileName, profileURL);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        ProfileDataInfo other = (ProfileDataInfo) obj;
        return Objects.equals(profileDescription, other.profileDescription)
                && Objects.equals(profileId, other.profileId) && Objects.equals(profileName, other.profileName)
                && Objects.equals(profileURL, other.profileURL);
    }

    public Element toDOM(Document document) {

        Element profileDataInfoElement = document.createElement("ProfileDataInfo");

        if (profileURL != null) {
            Element profileURLElement = document.createElement("profileURL");
            profileURLElement.appendChild(document.createTextNode(profileURL));
            profileDataInfoElement.appendChild(profileURLElement);
        }
        if (profileId != null) {
            Element profileIdElement = document.createElement("profileId");
            profileIdElement.appendChild(document.createTextNode(profileId));
            profileDataInfoElement.appendChild(profileIdElement);
        }
        if (profileName != null) {
            Element profileNameElement = document.createElement("profileName");
            profileNameElement.appendChild(document.createTextNode(profileName));
            profileDataInfoElement.appendChild(profileNameElement);
        }
        if (profileDescription != null) {
            Element profileDescriptionElement = document.createElement("profileDescription");
            profileDescriptionElement.appendChild(document.createTextNode(profileDescription));
            profileDataInfoElement.appendChild(profileDescriptionElement);
        }
        if (profileVisible != null) {
            Element profileVisibleElement = document.createElement("profileVisible");
            profileVisibleElement.appendChild(document.createTextNode(profileVisible.toString()));
            profileDataInfoElement.appendChild(profileVisibleElement);
        }
        if (profileEnable != null) {
            Element profileEnableElement = document.createElement("profileEnable");
            profileEnableElement.appendChild(document.createTextNode(profileEnable.toString()));
            profileDataInfoElement.appendChild(profileEnableElement);
        }
        if (profileEnableBy != null) {
            Element profileEnableByElement = document.createElement("profileEnableBy");
            profileEnableByElement.appendChild(document.createTextNode(profileEnableBy));
            profileDataInfoElement.appendChild(profileEnableByElement);
        }
        return profileDataInfoElement;
    }

    public static ProfileDataInfo fromDOM(Element profileDataInfoElement) {

        ProfileDataInfo profileDataInfo = new ProfileDataInfo();

        NodeList profileURLList = profileDataInfoElement.getElementsByTagName("profileURL");
        if (profileURLList.getLength() > 0) {
            profileDataInfo.setProfileURL(profileURLList.item(0).getTextContent());
        }
        NodeList profileIdList = profileDataInfoElement.getElementsByTagName("profileId");
        if (profileIdList.getLength() > 0) {
            profileDataInfo.setProfileId(profileIdList.item(0).getTextContent());
        }
        NodeList profileNameList = profileDataInfoElement.getElementsByTagName("profileName");
        if (profileNameList.getLength() > 0) {
            profileDataInfo.setProfileName(profileNameList.item(0).getTextContent());
        }
        NodeList profileDescriptionList = profileDataInfoElement.getElementsByTagName("profileDescription");
        if (profileDescriptionList.getLength() > 0) {
            profileDataInfo.setProfileDescription(profileDescriptionList.item(0).getTextContent());
        }
        NodeList profileVisibleList = profileDataInfoElement.getElementsByTagName("profileVisible");
        if (profileVisibleList.getLength() > 0) {
            profileDataInfo.setProfileVisible(Boolean.valueOf(profileVisibleList.item(0).getTextContent()));
        }
        NodeList profileEnableList = profileDataInfoElement.getElementsByTagName("profileEnable");
        if (profileEnableList.getLength() > 0) {
            profileDataInfo.setProfileEnable(Boolean.valueOf(profileEnableList.item(0).getTextContent()));
        }
        NodeList profileEnableByList = profileDataInfoElement.getElementsByTagName("profileEnableBy");
        if (profileEnableByList.getLength() > 0) {
            profileDataInfo.setProfileEnableBy(profileEnableByList.item(0).getTextContent());
        }
        return profileDataInfo;
    }

    public String toXML() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.newDocument();

        Element profileParameterElement = toDOM(document);
        document.appendChild(profileParameterElement);

        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");

        DOMSource domSource = new DOMSource(document);

        StringWriter sw = new StringWriter();
        StreamResult streamResult = new StreamResult(sw);
        transformer.transform(domSource, streamResult);
        return sw.toString();
    }

    public static ProfileDataInfo fromXML(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new InputSource(new StringReader(xml)));

        Element profileParameterElement = document.getDocumentElement();
        return fromDOM(profileParameterElement);
    }

}
