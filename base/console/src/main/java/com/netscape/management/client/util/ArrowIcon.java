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
import javax.swing.*;

public class ArrowIcon implements Icon {
    public static int NORTH = SwingConstants.NORTH;
    public static int SOUTH = SwingConstants.SOUTH;
    public static int EAST = SwingConstants.EAST;
    public static int WEST = SwingConstants.WEST;
    int _direction = NORTH;
    int _size = 3;

    /**
     * Contructs ArrowIcon with direction = NORTH and size = 3
     */
    public ArrowIcon() {
        this(NORTH, 3);
    }

    /**
      * Contructs ArrowIcon with the specified direction.
      * @param direction	Direction of the icon, NORTH, SOUTH, EAST, WEST
      */
    public ArrowIcon(int direction) {
        this(direction, 3);
    }

    /**
      * Contructs ArrowIcon with the specified direction and size.
      * @param direction	Direction of the icon, NORTH, SOUTH, EAST, WEST
      * @param size Size of icon in pixels (width and height are the same)
      */
    public ArrowIcon(int direction, int size) {
        setIconDirection(direction);
        setIconSize(size);
    }

    /**
      * Return icon direction.
      * @return Direction of icon NORTH, SOUTH, EAST, WEST
      */
    public int getIconDirection() {
        return _direction;
    }

    /**
      * Set icon direction.
      * @param direction Direction of icon NORTH, SOUTH, EAST, WEST
      */
    public void setIconDirection(int direction) {
        _direction = direction;
    }

    /**
      * return icon size (width and height are the same)
      * @return the icon height
      */
    public int getIconSize() {
        return _size;
    }

    /**
      * set icon size (width and height are the same)
      * @param size of the icon height
      */
    public void setIconSize(int size) {
        _size = size;
    }

    /**
      * subclassed from Icon
      * @return The fixed width of the icon.
      */
    public int getIconWidth() {
        return _size;
    }

    /**
      * subclassed from Icon
      * @return The fixed height of the icon.
      */
    public int getIconHeight() {
        return _size;
    }

    /**
      * paint the icon
      *
      * @param c component itself
      * @param g graphics to be paint on
      * @param x x location
      * @param y y location
      */
    public void paintIcon(Component c, Graphics g, int x, int y) {
        //boolean isEnabled = ((JButton) c).isEnabled();
        boolean isEnabled = c.isEnabled();
        int mid, i, j;
        Color oldColor = g.getColor();

        y--;
        j = 0;
        _size = Math.max(_size, 2);
        mid = _size / 2;


        g.translate(x, y);
        if (isEnabled)
            g.setColor(UIManager.getColor("controlDkShadow"));
        else
            g.setColor(UIManager.getColor("controlShadow"));

        switch (_direction) {
        case SwingConstants.NORTH:
            for (i = 0; i < _size; i++) {
                g.drawLine(mid - i, i, mid + i, i);
            }
            if (!isEnabled) {
                g.setColor(UIManager.getColor("controlHighlight"));
                g.drawLine(mid - i + 2, i, mid + i, i);
            }
            break;
        case SwingConstants.SOUTH:
            if (!isEnabled) {
                g.translate(1, 1);
                g.setColor(UIManager.getColor("controlHighlight"));
                for (i = _size - 1; i >= 0; i--) {
                    g.drawLine(mid - i, j, mid + i, j);
                    j++;
                }
                g.translate(-1, -1);
                g.setColor(UIManager.getColor("controlShadow"));
            }

            j = 0;
            for (i = _size - 1; i >= 0; i--) {
                g.drawLine(mid - i, j, mid + i, j);
                j++;
            }
            break;
        case SwingConstants.WEST:
            for (i = 0; i < _size; i++) {
                g.drawLine(i, mid - i, i, mid + i);
            }
            if (!isEnabled) {
                g.setColor(UIManager.getColor("controlHighlight"));
                g.drawLine(i, mid - i + 2, i, mid + i);
            }
            break;
        case SwingConstants.EAST:
            if (!isEnabled) {
                g.translate(1, 1);
                g.setColor(UIManager.getColor("controlHighlight"));
                for (i = _size - 1; i >= 0; i--) {
                    g.drawLine(j, mid - i, j, mid + i);
                    j++;
                }
                g.translate(-1, -1);
                g.setColor(UIManager.getColor("controlShadow"));
            }

            j = 0;
            for (i = _size - 1; i >= 0; i--) {
                g.drawLine(j, mid - i, j, mid + i);
                j++;
            }
            break;
        }
        g.translate(-x, -y);
        g.setColor(oldColor);
    }
}
