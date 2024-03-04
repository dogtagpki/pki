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

import java.awt.Graphics;
import java.awt.Insets;
import java.awt.Color;
import java.awt.Component;
import javax.swing.border.*;


/**
 * A table header border that has a flat (non-button like) border.
 * This type or border is necessary because the default
 * JTable header border looks like a button, which gives
 * the impression that it is clickable (sortable).
 *
 * @author ahakim@netscape.com
 */
public class SuiTableHeaderBorder extends AbstractBorder {
    /** Raised bevel type. */
    public static final int RAISED = 0;
    /** Lowered bevel type. */
    public static final int LOWERED = 1;

    protected int bevelType;
    protected Color highlightOuter;
    protected Color highlightInner;
    protected Color shadowInner;
    protected Color shadowOuter;

    /**
     * Creates a bevel border with the specified type and whose
     * colors will be derived from the background color of the
     * component passed into the paintBorder method.
     * @param bevelType the type of bevel for the border
     */
    public SuiTableHeaderBorder(int bevelType) {
        this.bevelType = bevelType;
    }

    /**
      * Creates a bevel border with the specified type, highlight and
      * shadow colors.
      * @param bevelType the type of bevel for the border
      * @param highlight the color to use for the bevel highlight
      * @param shadow the color to use for the bevel shadow
      */
    public SuiTableHeaderBorder(int bevelType, Color highlight,
            Color shadow) {
        this(bevelType, highlight.darker(), highlight, shadow,
                shadow.brighter());
    }

    /**
      * Creates a bevel border with the specified type, highlight
      * shadow colors.
      * @param bevelType the type of bevel for the border
      * @param highlightOuter the color to use for the bevel outer highlight
      * @param highlightInner the color to use for the bevel inner highlight
      * @param shadowOuter the color to use for the bevel outer shadow
      * @param shadowInner the color to use for the bevel inner shadow
      */
    public SuiTableHeaderBorder(int bevelType, Color highlightOuter,
            Color highlightInner, Color shadowOuter, Color shadowInner) {
        this(bevelType);
        this.highlightOuter = highlightOuter;
        this.highlightInner = highlightInner;
        this.shadowOuter = shadowOuter;
        this.shadowInner = shadowInner;
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
        if (bevelType == RAISED) {
            paintRaisedBevel(c, g, x, y, width, height);

        } else if (bevelType == LOWERED) {
            paintLoweredBevel(c, g, x, y, width, height);
        }
    }

    /**
      * Returns the insets of the border.
      * @param c the component for which this border insets value applies
      */
    public Insets getBorderInsets(Component c) {
        return new Insets(0, 5, 1, 3);
    }

    /**
      * Returns the outer highlight color of the bevel border.
      */
    public Color getHighlightOuterColor(Component c) {
        return highlightOuter != null ? highlightOuter :
                c.getBackground().brighter().brighter();
    }

    /**
      * Returns the inner highlight color of the bevel border.
      */
    public Color getHighlightInnerColor(Component c) {
        return highlightInner != null ? highlightInner :
                c.getBackground().brighter();
    }

    /**
      * Returns the inner shadow color of the bevel border.
      */
    public Color getShadowInnerColor(Component c) {
        return shadowInner != null ? shadowInner :
                c.getBackground().darker();
    }

    /**
      * Returns the outer shadow color of the bevel border.
      */
    public Color getShadowOuterColor(Component c) {
        return shadowOuter != null ? shadowOuter :
                c.getBackground().darker().darker();
    }

    /**
      * Returns the type of the bevel border.
      */
    public int getBevelType() {
        return bevelType;
    }

    /**
      * Returns whether or not the border is opaque.
      */
    public boolean isBorderOpaque() {
        return true;
    }

    protected void paintRaisedBevel(Component c, Graphics g, int x,
            int y, int width, int height) {
        Color oldColor = g.getColor();
        int h = height;
        int w = width;

        g.translate(x, y);

        g.setColor(getHighlightOuterColor(c));
        g.drawLine(w - 1, 0, w - 1, h - 1);

        g.setColor(getShadowInnerColor(c));
        g.drawLine(w - 2, 0, w - 2, h - 1);
        g.drawLine(0, h - 1, w - 2, h - 1);

        g.translate(-x, -y);
        g.setColor(oldColor);

    }

    protected void paintLoweredBevel(Component c, Graphics g, int x,
            int y, int width, int height) {
        Color oldColor = g.getColor();
        int h = height;
        int w = width;

        g.translate(x, y);

        g.setColor(getHighlightOuterColor(c));
        g.drawLine(w - 1, 0, w - 1, h - 1);

        g.setColor(getShadowInnerColor(c));
        g.drawLine(w, 0, w, h);
        g.drawLine(0, h, w, h);

        g.translate(-x, -y);
        g.setColor(oldColor);
    }

}
