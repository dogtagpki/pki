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
package com.netscape.management.nmclf;

import javax.swing.*;
import javax.swing.event.*;

/**
 * An extension of DefaultBoundedRangeModel this problem:
 * scrolling a JScrollpane by dragging its slider causes its
 * contents to be continually updated.  This occurs because
 * fireStateChanged always fires its event.
 *
 * The default behavior in this class is to only fire
 * stateChanged if getValueIsAdjusting() == false,
 * which causes the contents to be updated only when the
 * drag is completed.
 *
 * This behavior can be changed by using the
 * setUpdateWhileAdjusting() method.
 *
 * @author ahakim@netscape.com
 */
public class SuiBoundedRangeModel extends DefaultBoundedRangeModel {
    private boolean _updateWhileAdjusting = false;

    public SuiBoundedRangeModel() {
        super();
    }

    public SuiBoundedRangeModel(int value, int extent, int min, int max) {
        super(value, extent, min, max);
    }

    /**
      * Controls whether contents should scroll in real-time as
      * the scroll bar slider is dragged.  If false (default), then
      * the contents is only changed after the drag is completed.
      */
    public void setUpdateWhileAdjusting(boolean state) {
        _updateWhileAdjusting = state;
    }

    /**
      * Returns true if contents should scroll in real-time as
      * the scroll bar slider is dragged.
      */
    public boolean getUpdateWhileAdjusting() {
        return _updateWhileAdjusting;
    }

    /**
      * Run each ChangeListeners stateChanged() method.
      *
      * @see #setRangeProperties
      * @see EventListenerList
      */
    protected void fireStateChanged() {
        if (_updateWhileAdjusting || !getValueIsAdjusting()) {
            super.fireStateChanged();
        }
    }
}
