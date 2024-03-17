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
package com.netscape.management.client.components;

import java.awt.*;
import javax.swing.*;

/**
 * A border with clickable appearance.
 * Used in table columns that can be sorted.
 */
class ClickBorder extends FlatBorder
{
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
            int width, int height) 
    {
        Color oldColor = g.getColor();
        int h = height;
        int w = width;

        g.translate(x, y);

        g.setColor(UIManager.getColor("controlLtHighlight"));
        g.drawLine(0, 0, w, 0);
        g.drawLine(0, 0, 0, h);

        //g.setColor(UIManager.getColor("ScrollBar.background"));
        //g.drawLine(1, 1, w, 1);
        //g.drawLine(1, 1, 1, h);

        g.setColor(UIManager.getColor("controlShadow"));
        g.drawLine(1, h-1, w-1, h-1);
        g.drawLine(w-1, 0, w-1, h-1);

        g.translate(-x, -y);
        g.setColor(oldColor);
    }
}
