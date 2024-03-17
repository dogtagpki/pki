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
package com.netscape.management.client.acleditor;

import java.awt.Color;
import java.awt.Canvas;
import java.awt.Graphics;

/**
 * The is a custom component which will draw a horizontal line.
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.1 10/9/97
 */

public class HorizontalLine extends Canvas {
    // These really should be SystemColor controlHighlight and controlShadow,
    // but they seem to return random results...hmmm
    static Color light = new Color(0xe7, 0xe7, 0xe7);
    static Color shadow = new Color(0x6f, 0x6f, 0x6f);

    int thickness;

    public HorizontalLine(int w, int _thickness) {
        thickness = _thickness;
        setSize(w, thickness * 2);
    }

    public void paint(Graphics g) {
        int w = getSize().width;

        g.setColor(shadow);
        g.fillRect(0, 0, w, thickness);
        g.fillRect(0, thickness, thickness, thickness);
        g.setColor(light);
        g.fillRect(thickness, thickness, w - thickness, thickness);
    }
}
