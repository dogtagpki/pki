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
import javax.swing.*;
import javax.swing.text.*;
import javax.swing.border.*;

/**
 * A multi line text label.  Text is wrapped using
 * rules of JTextArea.
 */
public class TextDetailArea extends JTextArea {
    /**
     * Constructs a new TextDetailArea.  A default model is set, the initial string
     * is null, and rows/columns are set to 0.
     */
    public TextDetailArea() {
        this(null, null, 0, 0);
    }

    /**
      * Constructs a new TextDetailArea with the specified text displayed.
      * A default model is created and rows/columns are set to 0.
      *
      * @param text the text to be displayed, or null
      */
    public TextDetailArea(String text) {
        this(null, text, 0, 0);
    }

    /**
      * Constructs a new empty TextDetailArea with the specified number of
      * rows and columns.  A default model is created, and the initial
      * string is null.
      *
      * @param rows the number of rows >= 0
      * @param columns the number of columns >= 0
      */
    public TextDetailArea(int rows, int columns) {
        this(null, null, rows, columns);
    }

    /**
      * Constructs a new TextDetailArea with the specified text and number
      * of rows and columns.  A default model is created.
      *
      * @param text the text to be displayed, or null
      * @param rows the number of rows >= 0
      * @param columns the number of columns >= 0
      */
    public TextDetailArea(String text, int rows, int columns) {
        this(null, text, rows, columns);
    }

    /**
      * Constructs a new TextDetailArea with the given document model, and defaults
      * for all of the other arguments (null, 0, 0).
      *
      * @param doc  the model to use
      */
    public TextDetailArea(Document doc) {
        this(doc, null, 0, 0);
    }

    /**
      * Constructs a new TextDetailArea with the specified number of rows
      * and columns, and the given model.  All of the constructors
      * feed through this constructor.
      *
      * @param doc the model to use, or create a default one if null
      * @param text the text to be displayed, null if none
      * @param rows the number of rows >= 0
      * @param columns the number of columns >= 0
      */
    public TextDetailArea(Document doc, String text, int rows,
            int columns) {

        super(doc, text, rows, columns);

        getCaret().setVisible(false);
        setEditable(false);
        setOpaque(true);
        
        //if we call set line wrap to true here, it will cause
        //null pointer exception when the program start.
        //This is due to use of boxlayout in conjunction
        //with line wrap
        setLineWrap(true);

        setWrapStyleWord(true);

        setBorder(new CompoundBorder(new EmptyBorder(0,0,0,0), new EmptyBorder(5,5,5,5)));

    }

    public boolean isFocusTraversable() {
        return false;
    }
    
    /**
     * Adds a new text line into Text Detail Area
     *
     * @param text the text to be added to the Text Detail Area
     */
    public void addDetail(String text)
    {
        append("\n");
        if (text != null)
            append(text);
    }
}
