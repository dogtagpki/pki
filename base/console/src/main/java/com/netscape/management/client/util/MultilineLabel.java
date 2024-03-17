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
import javax.swing.text.*;
import javax.swing.border.*;

/**
 * A multi line text label.  Text is wrapped using
 * rules of JTextArea.
 */
public class MultilineLabel extends JTextArea {

    /**
     * Constructs a new MultilineLabel.  A default model is set, the initial string
     * is null, and rows/columns are set to 0.
     */
    public MultilineLabel() {
        this(null, null, 0, 0);
    }

    /**
      * Constructs a new MultilineLabel with the specified text displayed.
      * A default model is created and rows/columns are set to 0.
      *
      * @param text the text to be displayed, or null
      */
    public MultilineLabel(String text) {
        this(null, text, 0, 0);
    }

    /**
      * Constructs a new empty MultilineLabel with the specified number of
      * rows and columns.  A default model is created, and the initial
      * string is null.
      *
      * @param rows the number of rows >= 0
      * @param columns the number of columns >= 0
      */
    public MultilineLabel(int rows, int columns) {
        this(null, null, rows, columns);
    }

    /**
      * Constructs a new MultilineLabel with the specified text and number
      * of rows and columns.  A default model is created.
      *
      * @param text the text to be displayed, or null
      * @param rows the number of rows >= 0
      * @param columns the number of columns >= 0
      */
    public MultilineLabel(String text, int rows, int columns) {
        this(null, text, rows, columns);
    }

    /**
      * Constructs a new MultilineLabel with the given document model, and defaults
      * for all of the other arguments (null, 0, 0).
      *
      * @param doc  the model to use
      */
    public MultilineLabel(Document doc) {
        this(doc, null, 0, 0);
    }

    /**
      * Constructs a new MultilineLabel with the specified number of rows
      * and columns, and the given model.  All of the constructors
      * feed through this constructor.
      *
      * @param doc the model to use, or create a default one if null
      * @param text the text to be displayed, null if none
      * @param rows the number of rows >= 0
      * @param columns the number of columns >= 0
      */
    public MultilineLabel(Document doc, String text, int rows,
            int columns) {

        super(doc, text, rows, columns);

        getCaret().setVisible(false);
        setEditable(false);
        setOpaque(false);

        //if we call set line wrap to true here, it will cause
        //null pointer exception when the program start.
        //This is due to use of boxlayout in conjunction
        //with line wrap
        setLineWrap(true);

        setWrapStyleWord(true);

        getHighlighter().removeAllHighlights();
        setHighlighter(new InvisibleHighlighter());
        setBorder(new EmptyBorder(0, 0, 0, 0));

    }

    public boolean isFocusTraversable() {
        return false;
    }

    class InvisibleHighlighter implements Highlighter {
        //DefaultHighlighter highLighter = new DefaultHighlighter();
        public Object addHighlight(int p0, int p1,
                Highlighter.HighlightPainter p) {
            return null;//highLighter;
        }
        public void changeHighlight(Object tag, int p0, int p1) {}
        public void deinstall(JTextComponent c) {}
        public Highlighter.Highlight[] getHighlights() {
            return null;//highLighter.getHighlights();
        }
        public void install(JTextComponent c) {}
        public void paint(java.awt.Graphics g) {}
        public void removeAllHighlights() {}
        public void removeHighlight(Object tag) {}
    }    

    /**
     * Client property key used to determine what label is labeling the
     * component.  This is generally not used by labels, but is instead
     * used by components such as text areas that are being labeled by
     * labels.  When the labelFor property of a label is set, it will
     * automatically set the LABELED_BY_PROPERTY of the component being
     * labelled.
     *
     * @see #setLabelFor
     */
    static final String LABELED_BY_PROPERTY = "labeledBy";

    protected Component labelFor = null;

    /**
     * Get the component this is labelling.
     *
     * @return the Component this is labelling.  Can be null if this
     * does not label a Component.  If the displayedMnemonic
     * property is set and the labelFor property is also set, the label
     * will call the requestFocus method of the component specified by the
     * labelFor property when the mnemonic is activated.
     *
     * @see #getDisplayedMnemonic
     * @see #setDisplayedMnemonic
     */
    public Component getLabelFor() {
        return labelFor;
    }

    /**
     * Set the component this is labelling.  Can be null if this does not
     * label a Component.  If the displayedMnemonic property is set
     * and the labelFor property is also set, the label will
     * call the requestFocus method of the component specified by the
     * labelFor property when the mnemonic is activated.
     *
     * @param c  the Component this label is for, or null if the label is
     *           not the label for a component
     *
     * @see #getDisplayedMnemonic
     * @see #setDisplayedMnemonic
     *
     * @beaninfo
     *        bound: true
     *  description: The component this is labelling.
     */
    public void setLabelFor(Component c) {
        java.awt.Component oldC = labelFor;
        labelFor = c;
        firePropertyChange("labelFor", oldC, c);
        
        if (oldC instanceof JComponent) {
            ((JComponent)oldC).putClientProperty(LABELED_BY_PROPERTY, null);
        }
        if (c instanceof JComponent) {
            ((JComponent)c).putClientProperty(LABELED_BY_PROPERTY, this);
        }
    }


}
