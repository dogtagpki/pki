/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/
package com.netscape.management.client;

import java.awt.Component;

import javax.swing.JLabel;

import com.netscape.management.client.util.RemoteImage;

/**
 * Implements a status item that shows whether the connetion
 * is secure.
 *
 * @see IStatusItem
 */
public class StatusItemSecureMode extends JLabel implements IStatusItem {
    protected String _id = null;
    protected boolean _secureOn = false;
    protected static String _imageSource = "com/netscape/management/client/images/";
    static RemoteImage _securityOnIcon, _securityOffIcon;

    /**
     * Returns empty status component
     */
    public StatusItemSecureMode(String id) {
        setID(id);
        //setOpaque(true);
    }

    /**
     * Returns status component initialized with specified text.
     */
    public StatusItemSecureMode(String id, boolean secureOn) {
        this(id);
        setSecureMode(secureOn);
    }

    /**
     * Returns the associated view Component.
     */
    public Component getComponent() {
        return this;
    }

    /**
     * Returns unique, language independant ID.
     */
    public String getID() {
        return _id;
    }

    /**
     * Sets ID
     */
    public void setID(String id) {
        _id = id;
    }

    /**
     * Sets ID
     */
    public void setSecureMode(boolean state) {
        setState(Boolean.valueOf(state));
    }

    /**
     * Sets state.
     */
    public void setState(Object secureOn) {
        if (((Boolean) secureOn).booleanValue()) {
            if (_securityOnIcon == null) {
                _securityOnIcon = new RemoteImage(_imageSource + "secure.gif");
            }
            setIcon(_securityOnIcon);
        } else {
            if (_securityOffIcon == null) {
                _securityOffIcon = new RemoteImage(_imageSource + "notsecure.gif");
            }
            setIcon(_securityOffIcon);
        }
        invalidate();
        if (getParent() != null) {
            getParent().validate();
        }
        repaint();
    }

    /**
     * Returns current state.
     */
    public Object getState() {
        return getText();
    }
}












