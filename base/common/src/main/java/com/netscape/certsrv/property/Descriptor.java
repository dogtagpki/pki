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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.property;

import java.util.Locale;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.netscape.certsrv.util.JSONSerializer;


/**
 * This interface represents a property descriptor. A descriptor
 * includes information that describe a property.
 *
 * @version $Revision$, $Date$
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class Descriptor implements IDescriptor, JSONSerializer {

    @JsonProperty("Syntax")
    public String mSyntax = null;

    @JsonProperty("Constraint")
    public String mConstraint = null;

    @JsonProperty("Description")
    public String mDescription = null;

    @JsonProperty("DefaultValue")
    public String mDef = null;

    public Descriptor() {
    }

    /**
     * Constructs a descriptor.
     *
     * @param syntax syntax
     * @param constraint constraint
     * @param defValue default value
     * @param description description
     */
    public Descriptor(String syntax, String constraint, String defValue, String description) {
        mSyntax = syntax;
        mConstraint = constraint;
        mDef = defValue;
        mDescription = description;
    }

    /**
     * Returns the syntax of the property.
     *
     * @return syntax
     */
    @Override
    @JsonIgnore
    public String getSyntax() {
        return mSyntax;
    }

    /**
     * Returns the default value of the property.
     *
     * @return default value
     */
    @Override
    @JsonIgnore
    public String getDefaultValue() {
        return mDef;
    }

    /**
     * Constraint for the given syntax. For example,
     * <p>
     * - number(1-5): 1-5 is the constraint, and it indicates that the number must be in the range of 1 to 5.
     * <p>
     * - choice(cert,crl): cert,crl is the constraint for choice
     * <p>
     * If null, no constraint shall be enforced.
     * <p>
     *
     * @return constraint
     */
    @Override
    @JsonIgnore
    public String getConstraint() {
        return mConstraint;
    }

    /**
     * Retrieves the description of the property.
     *
     * @param locale user locale
     * @return description
     */
    @Override
    @JsonIgnore
    public String getDescription(Locale locale) {
        return mDescription;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((mConstraint == null) ? 0 : mConstraint.hashCode());
        result = prime * result + ((mDef == null) ? 0 : mDef.hashCode());
        result = prime * result + ((mDescription == null) ? 0 : mDescription.hashCode());
        result = prime * result + ((mSyntax == null) ? 0 : mSyntax.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        Descriptor other = (Descriptor) obj;
        if (mConstraint == null) {
            if (other.mConstraint != null)
                return false;
        } else if (!mConstraint.equals(other.mConstraint))
            return false;
        if (mDef == null) {
            if (other.mDef != null)
                return false;
        } else if (!mDef.equals(other.mDef))
            return false;
        if (mDescription == null) {
            if (other.mDescription != null)
                return false;
        } else if (!mDescription.equals(other.mDescription))
            return false;
        if (mSyntax == null) {
            if (other.mSyntax != null)
                return false;
        } else if (!mSyntax.equals(other.mSyntax))
            return false;
        return true;
    }

    public void toDOM(Document document, Element element) {

        if (mSyntax != null) {
            Element syntaxElement = document.createElement("Syntax");
            syntaxElement.appendChild(document.createTextNode(mSyntax));
            element.appendChild(syntaxElement);
        }

        if (mConstraint != null) {
            Element constraintElement = document.createElement("Constraint");
            constraintElement.appendChild(document.createTextNode(mConstraint));
            element.appendChild(constraintElement);
        }

        if (mDescription != null) {
            Element descriptionElement = document.createElement("Description");
            descriptionElement.appendChild(document.createTextNode(mDescription));
            element.appendChild(descriptionElement);
        }

        if (mDef != null) {
            Element defaultValueElement = document.createElement("DefaultValue");
            defaultValueElement.appendChild(document.createTextNode(mDef));
            element.appendChild(defaultValueElement);
        }
    }

    public Element toDOM(Document document) {
        Element element = document.createElement("Descriptor");
        toDOM(document, element);
        return element;
    }

    public static Descriptor fromDOM(Element element) {

        Descriptor descriptor = new Descriptor();

        NodeList syntaxList = element.getElementsByTagName("Syntax");
        if (syntaxList.getLength() > 0) {
            descriptor.mSyntax = syntaxList.item(0).getTextContent();
        }

        NodeList constraintList = element.getElementsByTagName("Constraint");
        if (constraintList.getLength() > 0) {
            descriptor.mConstraint = constraintList.item(0).getTextContent();
        }

        NodeList descriptionList = element.getElementsByTagName("Description");
        if (descriptionList.getLength() > 0) {
            descriptor.mDescription = descriptionList.item(0).getTextContent();
        }

        NodeList defaultValueList = element.getElementsByTagName("DefaultValue");
        if (defaultValueList.getLength() > 0) {
            descriptor.mDef = defaultValueList.item(0).getTextContent();
        }

        return descriptor;
    }
}
