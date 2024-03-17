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

import java.awt.Graphics;
import java.awt.Insets;
import java.awt.Color;
import java.awt.Component;
import javax.swing.plaf.basic.*;
import javax.swing.border.*;
import com.netscape.management.nmclf.*;


/**
 * A border type that appears as dots, sort of like Windows.
 *
 * @author ahakim@netscape.com
 * @todo   move to nmclf
 */
public class DottedBorder extends AbstractBorder implements SuiConstants {
    protected Color _dotColor;
    protected boolean _isTopVisible = true;
    protected boolean _isLeftVisible = true;
    protected boolean _isBottomVisible = true;
    protected boolean _isRightVisible = true;

    /**
     * Constructor
     */
    public DottedBorder() {
        _dotColor = Color.black;
    }

    /**
      * Constructor which specifies borders that are visible
      * @param top     whether top side is visible
      * @param left    whether left side is visible
      * @param bottom  whether bottom side is visible
      * @param right   whether right side is visible
      */
    public DottedBorder(boolean top, boolean left, boolean bottom,
            boolean right) {
        _dotColor = Color.black;
        _isTopVisible = top;
        _isLeftVisible = left;
        _isBottomVisible = bottom;
        _isRightVisible = right;
    }

    /**
      * Paints the border for the specified component with the specified
      * position and size.
      * @param c the component for which this border is being painted
      * @param g the paint graphics
      * @param x the x position of the painted border
      * @param y the y position of the painted border
      * @param width the width of the painted border
      * @param height the height of the painted border
      */
    public void paintBorder(Component c, Graphics g, int x, int y,
            int width, int height) {
        Color oldColor = g.getColor();
        g.translate(x, y);
        g.setColor(_dotColor);

        int x1 = 0;
        int y1 = 0;
        int x2 = width;
        int y2 = height;

        if (!_isTopVisible)
            y1 = -1;
        if (!_isLeftVisible)
            x1 = -1;
        if (!_isBottomVisible)
            y2 += 1;
        if (!_isRightVisible)
            x2 += 2;

        BasicGraphicsUtils.drawDashedRect(g, x1, y1, x2, y2);

        g.translate(-x, -y);
        g.setColor(oldColor);
    }

    /**
      * Returns the insets of the border.
      * @param c the component for which this border insets value applies
      * @return insets of the border
      */
    public Insets getBorderInsets(Component c) {
        return new Insets(VERT_COMPONENT_INSET + 2,
                HORIZ_COMPONENT_INSET + 2, VERT_COMPONENT_INSET + 1,
                HORIZ_COMPONENT_INSET);
    }

    /**
      * Returns whether or not the border is opaque.
      * @return  true to indicate border is opaque
      */
    public boolean isBorderOpaque() {
        return true;
    }
}
