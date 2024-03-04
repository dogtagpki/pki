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

import java.awt.Color;
import java.awt.Component;
import java.io.Serializable;

import javax.swing.Icon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.UIManager;
import javax.swing.table.TableCellRenderer;


/**
 * A special version of DefaultCellRenderer from JFC code
 * that fixes a bug (unknown), used by acleditor.RightsDataModel.java
 *
 * @todo remove or move to acleditor package.
 */
public class DefaultCellRenderer implements TableCellRenderer,
Serializable {

    // PENDING(alan): Should use system selection color
    protected final static Color selectionColor = new Color(0, 0, 128);

    //
    // Instance Variables
    //

    protected JComponent component;
    protected ValueProperty value;

    protected Color backgroundColor;
    protected Color foregroundColor;
    protected Color selectedBackgroundColor;
    protected Color selectedForegroundColor;

    //
    // Constructors
    //

    public DefaultCellRenderer(JLabel x) {
        this.component = x;
        x.setOpaque(true);
        this.value = new ValueProperty() {
                    public void setValue(Object x) {
                        // Set value to empty string so it will display a
                        // blank cell, and not cause an exception
                        if (x == null)
                            x = "";

                        super.setValue(x);
                        if (x instanceof Icon)
                            ((JLabel) component).setIcon((Icon) x);
                        else
                            ((JLabel) component).setText(x.toString());
                    }
                };

        // Default label colors
        /*
        setBackgroundColor(Color.white);
        setForegroundColor(Color.black);
        setSelectedBackgroundColor(selectionColor);
        setSelectedForegroundColor(Color.white);
        */
    }

    public DefaultCellRenderer(JButton x) {
        this.component = x;
        this.value = new ValueProperty() {
                    public void setValue(Object x) {
                        // Set value to empty string so it will display a
                        // blank button, and not cause an exception
                        if (x == null)
                            x = "";

                        super.setValue(x);
                        ((JButton) component).setText(x.toString());
                    }
                };

        // Default button colors
        /*
        setBackgroundColor(Color.lightGray);
        setForegroundColor(Color.black);
        setSelectedBackgroundColor(Color.darkGray);
        setSelectedForegroundColor(Color.white);
               */
    }

    public DefaultCellRenderer(JCheckBox x) {
        this.component = x;
        this.value = new ValueProperty() {
                    public void setValue(Object x) {
                        // Set value to empty string so it will not
                        // cause an exception
                        if (x == null)
                            x = "";

                        super.setValue(x);

                        // Try my best to do the right thing with x
                        if (x instanceof Boolean) {
                            ((JCheckBox) component).setSelected(
                                    ((Boolean) x).booleanValue());
                        } else if (x instanceof String) {
                            Boolean b = Boolean.valueOf((String) x);
                            ((JCheckBox) component).setSelected(
                                    b.booleanValue());
                        } else {
                            ((JCheckBox) component).setSelected(false);
                        }
                    }
                };

        // Default checkbox colors
        /*
        setBackgroundColor(Color.white);
        setForegroundColor(Color.black);
        setSelectedBackgroundColor(selectionColor);
        setSelectedForegroundColor(Color.white);
        */
    }

    //
    // Modifying and Querying
    //

    public void setBackgroundColor(Color newColor) {
        backgroundColor = newColor;
    }

    public Color getBackgroundColor() {
        return backgroundColor;
    }

    public void setForegroundColor(Color newColor) {
        foregroundColor = newColor;
    }

    public Color getForegroundColor() {
        return foregroundColor;
    }

    public void setSelectedBackgroundColor(Color newColor) {
        selectedBackgroundColor = newColor;
    }

    public Color getSelectedBackgroundColor() {
        return selectedBackgroundColor;
    }

    public void setSelectedForegroundColor(Color newColor) {
        selectedForegroundColor = newColor;
    }

    public Color getSelectedForegroundColor() {
        return selectedForegroundColor;
    }

    public void setToolTipText(String text) {
        if (component instanceof JComponent)
            component.setToolTipText(text);
    }

    public Component getComponent() {
        return component;
    }

    //
    // Implementing TableCellRenderer
    //

    public Component getTableCellRendererComponent(JTable table,
            Object value, boolean isSelected, boolean hasFocus,
            int row, int column) {
        // PENDING(philip): Hacks for Motif L&F.
        // The muddle of if clauses below are minimal hacks that were included
        // to make the motif L&F table use the correct selection colors
        // for the for the first motif L&F release.
        // This all needs to be redone.
        if (isSelected) {
            if (selectedBackgroundColor == null) {
                component.setBackground(UIManager.getColor("textHighlight"));
            } else {
                component.setBackground(selectedBackgroundColor);
            }
            if (selectedForegroundColor == null) {
                component.setForeground(UIManager.getColor("textHighlightText"));
            } else {
                component.setForeground(selectedForegroundColor);
            }
        } else {
            //    if (backgroundColor != null) {
            component.setBackground(backgroundColor);
            //    }
            //    else {
            //        component.setBackground(Color.white);
            //    }
            //    if (foregroundColor != null) {
            component.setForeground(foregroundColor);
            //    }
            //    else {
            //        component.setForeground(Color.black);
            //    }
        }

        this.value.setValue(value);
        return component;
    }


    protected class ValueProperty implements Serializable {
        protected Object value;

        public void setValue(Object x) {
            this.value = x;
        }
    }


}


