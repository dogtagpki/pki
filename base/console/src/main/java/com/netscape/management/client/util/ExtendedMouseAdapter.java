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

package com.netscape.management.client.util;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;

/**
 * ExtendedMouseAdaptor was developed to determine whether a double click
 * occurred on a button. This is not necessary in that MouseEvent already
 * supports this.
 */
public class ExtendedMouseAdapter extends MouseAdapter {
    public static long DOUBLE_CLICK_INTERVAL = 1000;
    protected long _previousTimeStamp = 0;
    Point _previousPoint = new Point(0, 0);
    JButton _doubleClickButton;

    public ExtendedMouseAdapter() {
        super();
    }

    public ExtendedMouseAdapter(JButton b) {
        setDoubleClickButton(b);
    }

    public void setDoubleClickButton(JButton b) {
        _doubleClickButton = b;
    }

    public void mouseClicked(MouseEvent e) {
        Point currentPoint = e.getPoint();
        if ((currentPoint.x == _previousPoint.x) &&
                (currentPoint.y == _previousPoint.y)) {
            long currentTimeStamp = System.currentTimeMillis();
            if (((currentTimeStamp - _previousTimeStamp) >
                    DOUBLE_CLICK_INTERVAL)) {
                _previousTimeStamp = currentTimeStamp;
                mouseDoubleClicked(e);
            }
        }
        _previousPoint = currentPoint;
    }

    public void mouseDoubleClicked(MouseEvent e) {
        if (_doubleClickButton != null) {
            _doubleClickButton.doClick();
        }
    }
}

