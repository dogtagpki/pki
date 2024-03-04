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

import java.awt.*;
import javax.swing.*;
import javax.swing.tree.*;
import javax.swing.plaf.basic.*;

/**
 * A specialized tree cell renderer for use with the ResourcePage tree.
 * This class offers the following improvements over JFC's DefaultTreeCellRenderer:
 *
 * - handles multiple-selection/focus color behavior
 * - uses 'better' preferred size (UE defined)
 * - paints dotted border around text
 *
 * TODO:
 * monitor JFC progress and remove functionality from this class as JFC adds it
 * make it PLAF friendly
 * move to nmclf
 */
public class ResourceCellRenderer extends JLabel implements TreeCellRenderer {
    boolean _isSelected = false;
    boolean _isMultipleSelection = false;
    boolean _hasFocus = false;
    boolean _hasTreeFocus = false;
    Color foregroundSelected;
    Color backgroundSelected;
    Color foregroundUnselected;
    Color backgroundUnselected;
    Color foregroundSelectedUnfocus;
    Color backgroundSelectedUnfocus;

    public ResourceCellRenderer() {
        setHorizontalAlignment(JLabel.LEFT);

        foregroundSelected = UIManager.getColor("textHighlightText");
        backgroundSelected = UIManager.getColor("textHighlight");

        foregroundUnselected = UIManager.getColor("controlText");
        backgroundUnselected = UIManager.getColor("window");

        foregroundSelectedUnfocus = UIManager.getColor("controlText");
        backgroundSelectedUnfocus = UIManager.getColor("control");
    }

    public void updateUI() {
        super.updateUI();
        setBackground(null);
    }

    /**
       * Returns true if multple objects are selected
       */
    public boolean isMultipleSelection(JTree tree) {
        TreePath path[] = tree.getSelectionPaths();
        if ((path != null) && (path.length > 0)) {
            return true;
        }
        return false;
    }


    /**
     * Configures the renderer based on the passed in components.
     * The value is set from messaging value with toString().
     * The foreground color is set based on the selection and the icon
     * is set based on on leaf and expanded.
     */
    public Component getTreeCellRendererComponent(JTree tree,
            Object value, boolean selected, boolean expanded,
            boolean leaf, int row, boolean hasFocus) {
        _hasTreeFocus = tree.hasFocus();
        _isMultipleSelection = isMultipleSelection(tree);
        _hasFocus = hasFocus;
        _isSelected = selected;

        if (_isSelected) {
            if ((_hasFocus || _isMultipleSelection) && _hasTreeFocus)//if(_hasFocus || _isMultipleSelection)

                setForeground(foregroundSelected);
            else
                setForeground(foregroundSelectedUnfocus);
        } else {
            setForeground(foregroundUnselected);
        }

        if (value instanceof IResourceObject) {
            IResourceObject obj = (IResourceObject) value;
            setIcon(obj.getIcon());
            setText(obj.getName());
            setFont(UIManager.getFont("Tree.font"));
        } else
            setText( tree.convertValueToText(value, selected, expanded,
                    leaf, row, hasFocus));

        return this;
    }

    public void paint(Graphics g) {
        Color backgroundColor;
        Icon icon = getIcon();
        int iconTextGap = getIconTextGap();
        String s = getText();
        int offset = 0;
        int width = 0;
        FontMetrics fm = getToolkit().getFontMetrics(getFont());
        
        if (s != null)
            width = SwingUtilities.computeStringWidth(fm, s);
        int height = fm.getHeight() + 2;

        if (icon != null)
            offset = icon.getIconWidth() + iconTextGap;

        if (_isSelected) {
            if ((_hasFocus || _isMultipleSelection) && _hasTreeFocus)
                backgroundColor = backgroundSelected;
            else
                backgroundColor = backgroundSelectedUnfocus;
        } else {
            backgroundColor = backgroundUnselected;
        }

        g.setColor(backgroundColor);

        if (icon != null && getText() != null) {
            g.fillRect(offset + 1, 1, width, height);
        } else {
            g.fillRect(1, 1, width, height);
        }

        super.paint(g);

        if (_isSelected) {
            if (_hasFocus) {
                g.setColor(Color.black); // TODO: hard-coded value
                BasicGraphicsUtils.drawDashedRect(g, offset, 0,
                                                  width, height);
            } else {
                g.setColor(backgroundColor);
                g.drawRect(offset, 0, width, height);
            }
        }
    }

    public Dimension getPreferredSize() {
        Dimension retDimension = super.getPreferredSize();

        if (retDimension != null)
            retDimension = new Dimension(retDimension.width + 3,
                    retDimension.height);

        return retDimension;
    }
}
