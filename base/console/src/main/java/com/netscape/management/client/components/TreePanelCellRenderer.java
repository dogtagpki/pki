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
import javax.swing.tree.*;
import javax.swing.plaf.basic.BasicGraphicsUtils;

/**
 * TreePanelCellRenderer
 * 
 *
 * @version 1.0
 * @author rweltman
 **/

public class TreePanelCellRenderer extends JLabel
                                   implements TreeCellRenderer {

    public TreePanelCellRenderer() {
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
												  Object value,
												  boolean selected,
												  boolean expanded,
												  boolean leaf,
												  int row,
												  boolean hasFocus) {
        _hasTreeFocus = tree.hasFocus();
        _isMultipleSelection = isMultipleSelection(tree);
        _hasFocus = hasFocus;
        _isSelected = selected;

        if (_isSelected) {
            if ((_hasFocus || _isMultipleSelection) && _hasTreeFocus)
                setForeground(foregroundSelected);
            else
                setForeground(foregroundSelectedUnfocus);
        } else {
            setForeground(foregroundUnselected);
        }

        if (value instanceof IDirNode) {
            IDirNode obj = (IDirNode) value;
            setIcon(obj.getIcon());
            setText(obj.getName());
            setFont(UIManager.getFont("Tree.font"));
            setToolTipText(obj.getDN());
        } else {
            setText( tree.convertValueToText(value, selected, expanded,
                    leaf, row, hasFocus));
        }

        return this;
    }

    public void paint(Graphics g) {
        Color backgroundColor;
        Icon icon = getIcon();
        int iconTextGap = getIconTextGap() - 2;
        int offset = 0;
        int width = getWidth();
        int height = getHeight();

        if (iconTextGap < 0)
            iconTextGap = 0;

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
            g.fillRect(offset + 1, 1, width - 2 - offset, height - 2);
        } else {
            g.fillRect(1, 1, width - 2 - offset, height - 2);
        }

        super.paint(g);

        if (_isSelected) {
            if (_hasFocus) {
                g.setColor(Color.black); // TODO: hard-coded value
                 BasicGraphicsUtils.drawDashedRect(g, offset, 0,
                         width - 1 - offset, height);
            } else {
                g.setColor(backgroundColor);
                g.drawRect(offset, 0, width - 1 - offset, height - 1);
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

    private boolean _isSelected = false;
    private boolean _isMultipleSelection = false;
    private boolean _hasFocus = false;
    private boolean _hasTreeFocus = false;
    private Color foregroundSelected;
    private Color backgroundSelected;
    private Color foregroundUnselected;
    private Color backgroundUnselected;
    private Color foregroundSelectedUnfocus;
    private Color backgroundSelectedUnfocus;
}
