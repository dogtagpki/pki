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
// --- END COPYRIGHT BLOCK ---

/**
 *
 */
package com.netscape.cms.servlet.profile.model;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * @author jmagne
 *
 */

@XmlRootElement(name = "ProfileData")
@XmlAccessorType(XmlAccessType.FIELD)
public class ProfileData {

    @XmlElement
    protected String id;
    @XmlElement
    protected String name;

    @XmlElement
    protected String description;

    @XmlElement
    protected boolean isEnabled;

    @XmlElement
    protected boolean isVisible;

    @XmlElement
    protected String enabledBy;

    @XmlElement(name = "Input")
    protected List<ProfileInput> inputs = new ArrayList<ProfileInput>();

    public void setName(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }

    public void setIsEnabled(boolean isEnabled) {
        this.isEnabled = isEnabled;
    }

    public boolean getIsEnabled() {
        return isEnabled;
    }

    public void setIsVisible(boolean isVisible) {
        this.isVisible = isVisible;
    }

    public boolean getIsVisible() {
        return isVisible;
    }

    public void setEnabledBy(String enabledBy) {
        this.enabledBy = enabledBy;
    }

    public String getEnabledBy() {
        return enabledBy;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getId() {
        return id;
    }

    public ProfileInput addProfileInput(String name) {

        ProfileInput oldInput = getProfileInput(name);

        if (oldInput != null)
            return oldInput;

        ProfileInput newInput = new ProfileInput();
        newInput.setInputId(name);

        inputs.add(newInput);

        return newInput;
    }

    public ProfileInput getProfileInput(String name) {

        ProfileInput input = null;

        Iterator<ProfileInput> it = inputs.iterator();

        ProfileInput curInput = null;
        while (it.hasNext()) {
            curInput = it.next();

            if (curInput != null && curInput.getInputId().equals(name))
                break;
        }

        return input;
    }

    public List<ProfileInput> getProfileInputsList() {
        return inputs;
    }

}