// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.admin.certsrv;

import java.util.*;
import javax.swing.*;
import javax.swing.plaf.basic.*; //<JFC1.0>
//<JFC0.7>import javax.swing.basic.*;
import javax.swing.plaf.*;
import java.awt.event.ActionEvent;
import java.awt.Component;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.Rectangle;
import java.awt.Insets;
import java.awt.Color;
import java.awt.Graphics;
import java.awt.Font;
import java.awt.FontMetrics;
import java.io.Serializable;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import javax.swing.AbstractAction;

/**
 * Specific UI to handle to the line wrap for the multi-line log entries.
 *
 * This UI component extends the BasicLabelUI to handle multi-line label.
 * NOTE:
 * [1] This class does not break up the lines automatically. It relies on
 * '\n' in input text.
 * [2] This UI implementation can NOT be shared between components. Each
 * JLabel instance needs to install its own instance of MultilineLabelUI.
 * TODO:
 * [1] clipping, append "..."
 * [2] auto wrapping
 *
 * @version $Revision$, $Date$
 */
public class MultilineLabelUI extends BasicLabelUI {

    /**
     * Replaced with our own layout routine.
     *
     * @see SwingUtilities#layoutCompoundLabel
     */
    protected String layoutCL(
        JLabel label,
        FontMetrics fontMetrics,
    	String text,
    	Icon icon,
    	Rectangle viewR,
    	Rectangle iconR,
    	Rectangle textR)
    {
        return layoutCompoundLabel(
            fontMetrics,
    	    text,
    	    icon,
    	    label.getVerticalAlignment(),
    	    label.getHorizontalAlignment(),
    	    label.getVerticalTextPosition(),
    	    label.getHorizontalTextPosition(),
    	    viewR,
    	    iconR,
    	    textR,
    	    label.getIconTextGap());
    }

    /**
     * Paint the label text in the foreground color, if the label
     * is opaque then paint the entire background with the background
     * color.  The Label text is drawn by paintEnabledText() or
     * paintDisabledText().  The locations of the label parts are computed
     * by layoutCL.
     *
     * @see #paintEnabledText
     * @see #paintDisabledText
     * @see #layoutCL
     */
    public void paint(Graphics g, JComponent c) {
    	JLabel label = (JLabel)c;
    	String text = label.getText();
    	Icon icon = (label.isEnabled()) ? label.getIcon() : label.getDisabledIcon();
    	int i;

    	if ((icon == null) && (text == null)) {
    	    return;
    	}

    	//g.setFont(label.getFont());
    	FontMetrics fm = g.getFontMetrics();
    	Rectangle iconR = new Rectangle();
    	Rectangle textR = new Rectangle();
    	Rectangle viewR = new Rectangle(c.getSize());
    	Insets viewInsets = c.getInsets();

    	viewR.x = viewInsets.left;
    	viewR.y = viewInsets.top;
    	viewR.width -= (viewInsets.left + viewInsets.right);
    	viewR.height -= (viewInsets.top + viewInsets.bottom);

        //Debug.println("---> Calling layoutCL from paint");
    	layoutCL(label, fm, text, icon, viewR, iconR, textR);

    	if (icon != null) {
    	    icon.paintIcon(null, g, iconR.x, iconR.y);
    	}

    	int horizontalAlignment = ((JLabel)c).getHorizontalAlignment();

    	if (text != null) {
    	    int textX = textR.x;
    	    int textY = textR.y + fm.getAscent();
    	    char accChar = (char)label.getDisplayedMnemonic(); //<JFC1.0>
    	    //<JFC0.7>char accChar = (char)label.getDisplayedKeyAccelerator();
    	    char tmpChar;
    	    int h = fm.getHeight();

            int firstAccCharLine = findAccChar(textVector, accChar);

            /* NOTE: draws each string in the textVector */
    	    if (label.isEnabled()) {
        		g.setColor(label.getForeground());
        		for (i = 0; i < textVector.size(); i++) {
        		    if (i == firstAccCharLine) {
        		        tmpChar = accChar;
        		    }
        		    else {
        		        tmpChar = '\0';
        		    }
        		    BasicGraphicsUtils.drawString(g,
        		        (String)textVector.elementAt(i), tmpChar,
        		        offsetArray[0], textY+h*i);
        		        //offsetArray[i], textY+h*i);
        		}
    	    }
    	    else {
        		g.setColor(Color.gray);
        		for (i = 0; i < textVector.size(); i++) {
        		    if (i == firstAccCharLine) {
        		        tmpChar = accChar;
        		    }
        		    else {
        		        tmpChar = '\0';
        		    }
        		    BasicGraphicsUtils.drawString(g,
        		        (String)textVector.elementAt(i), tmpChar,
        		        offsetArray[i], textY+h*i);
        		}
        		g.setColor(Color.white);
        		for (i = 0; i < textVector.size(); i++) {
        		    if (i == firstAccCharLine) {
        		        tmpChar = accChar;
        		    }
        		    else {
        		        tmpChar = '\0';
        		    }
        		    BasicGraphicsUtils.drawString(g,
        		        (String)textVector.elementAt(i), tmpChar,
        		        offsetArray[i] + 1, textY + 1 + h*i);
        		}
    	    }
    	}
    }

    public Dimension getPreferredSize(JComponent c) {
        Dimension realSize = super.getPreferredSize(c);
        //Debug.println("MultilineLabelUI: realSize " + realSize);
        int width, height;

	    /* if preferred width is set, always use the preferred width
	     */
	    if (preferredSize != null) {
	        width = preferredSize.width;
	    }
	    else {
	        width = realSize.width;
	    }
	    /* compare computed height with the preferred height,
	     * return whichever is larger
	     */
	    height = realSize.height;
	    if (preferredSize != null) {
    	    height = preferredSize.height > height ?
    	        preferredSize.height : height;
	    }
        Dimension result = new Dimension(width, height);
        //Debug.println("MultilineLabelUI: preferredSize " + result);
        return result;
    }

    private final int computeStringVWidth(FontMetrics fm, Vector strV, int[] widthA) {
    	int w = 0, width = 0;
    	//Debug.println("computeStringWidth: vsize " + strV.size());
    	for (int i = 0; i < strV.size(); i++) {
    	    w = SwingUtilities.computeStringWidth(fm, (String)strV.elementAt(i));
        	//Debug.println("computeStringWidth: w for " + (String)strV.elementAt(i) + " is " + w);
    	    widthA[i] = w;
    	    if (w > width) width = w;
    	}
    	//Debug.println("computeStringWidth: width " + width);
    	return width;
    }

    public static ComponentUI createUI(JComponent c) {
    	return new MultilineLabelUI();
    }

    /* NOTE: " " has to be the first entry */
    static final String[] SEPARATORS = {" ", ".", ",", "?", "-", ":", ";", "!", "/", "\\"};
    Vector textVector;
    int[] widthArray;
    int[] offsetArray;

    protected Dimension preferredSize;

    boolean _parsed = false;

    public void parse() {
        _parsed = false;
    }

    /**
     * Only the preferred width is observed. MultilineLabelUI will break
     * the input text into multiple lines by calling wrapString. Derived
     * class should overrid wrapString to provide different parsing behavior.
     * The result of wrapString will determine the preferred height of this
     * component.
     */
    public void setWrap(int width) {
        if (preferredSize == null) {
            preferredSize = new Dimension();
        }
        preferredSize.width = width;
    }

    /**
     * This method break the input text into a vector of strings.
     * The default implementation is based on '\n' in the text.
     * Override this method to provide different parsing behavior.
     * wrapString expects the input string to be the last element
     * in the vector.
     */
    protected void wrapString(Vector v, FontMetrics fm, int w, String[] separators) {
        String s = (String)v.lastElement();
        //Debug.println("----> calling wrapString with " + s);
        if ((null == s) || ("".equals(s))) {
            return;
        }
        if (fm.stringWidth(s) > w) {
            String s1 = s, s2 = "";
            int i = -1;
            int j;
            int k;
            while (fm.stringWidth(s1) > w) {
                for (j = 0; j < separators.length; j++) {
                    i = s1.lastIndexOf(separators[j]);
                    if (i != -1 && i != (s1.length()-1)) {
                        break;
                    }
                }
                if (i == -1) {
                    for (k = s1.length()-1; k > 1; k--) {
                        String test = s1.substring(0, k-1);
                        if (fm.stringWidth(test) < w) {
                            s1 = test;
                            s2 = s.substring(s1.length());
                            break;
                        }
                    }
                }
                else {
                    s1 = (s1.substring(0, i+1)).trim();
                    s2 = s.substring(i+1);
                }
            }
            v.removeElementAt(v.size() - 1);
            v.addElement(s1);
            v.addElement(s2.trim());
            wrapString(v, fm, w, separators);
        }
        else {
            return;
        }
    }

    protected void parseTextV(String text, Vector textV) {
    	if (text == null || "".equals(text)) {
    	    textV.addElement("");
    	    return;
    	}

    	char[] textContent = text.toCharArray();
    	int begin = 0, end = 0;
    	for (end = 0; end < textContent.length; end++) {
    	    if (textContent[end] == '\n') {
        		textV.addElement(new String(textContent, begin, end - begin));
        		begin = end + 1;
    	    }
        }
        if (begin != textContent.length) {
            textV.addElement(new String(textContent, begin, end - begin));
        }
    }

    public String layoutCompoundLabel(
        FontMetrics fm,
        String text,
        Icon icon,
    	int verticalAlignment,
    	int horizontalAlignment,
    	int verticalTextPosition,
    	int horizontalTextPosition,
        Rectangle viewR,
    	Rectangle iconR,
    	Rectangle textR,
    	int textIconGap)
    {
    	/* Initialize the icon bounds rectangle iconR.
    	 */

    	if (icon != null) {
    	    iconR.width = icon.getIconWidth();
    	    iconR.height = icon.getIconHeight();
    	}
    	else {
    	    iconR.width = iconR.height = 0;
    	}

    	/* Initialize the text bounds rectangle textR.  If a null
    	 * or and empty String was specified we substitute "" here
    	 * and use 0,0,0,0 for textR.
    	 */

    	boolean textIsEmpty = (text == null) || text.equals("");

    	/* Unless both text and icon are non-null, we effectively ignore
    	 * the value of textIconGap.  The code that follows uses the
    	 * value of gap instead of textIconGap.
    	 */

    	int gap = (textIsEmpty || (icon == null)) ? 0 : textIconGap;

        /* NOTE: break up the text into multiple lines */
        /* TODO: clean up parseTextV and wrapString */
        if (!_parsed) {
        textVector = new Vector();
        if (preferredSize != null) {
            /* remove newline before calling wrapString
            if (!textIsEmpty) {
                text = text.replace('\n', ' ');
            }
            textVector.addElement(text);
            */

            int iconW;
            iconW = (icon == null) ? 0 : icon.getIconWidth();

            Vector tmp = new Vector();
            //Debug.println("calling parseTextV with " + text);
            parseTextV(text, tmp);
            for (Enumeration e = tmp.elements(); e.hasMoreElements(); ) {
                String subs = (String)e.nextElement();
                //Debug.println("parseTextV returns " + subs);
                textVector.addElement(subs);
            	wrapString(textVector, fm, preferredSize.width - gap - iconW, SEPARATORS);
            }
        }
        else {
            parseTextV(text, textVector);
        }
        _parsed = true;
        }
        widthArray = new int[textVector.size()];
        offsetArray = new int[widthArray.length];

    	if (textIsEmpty) {
    	    textR.width = textR.height = 0;
    	    text = "";
    	}
    	else {
	        textR.width = computeStringVWidth(fm,textVector,widthArray);
    	    textR.height = fm.getHeight() * textVector.size();
    	}

    /* NOTE: we need to handle clipped case
    	if (!textIsEmpty) {

    	    int availTextWidth;

    	    if (horizontalTextPosition == CENTER) {
    		availTextWidth = viewR.width;
    	    }
    	    else {
    		availTextWidth = viewR.width - (iconR.width + gap);
    	    }


    	    if (textR.width > availTextWidth) {
    		String clipString = "...";
    		int totalWidth = computeStringWidth(fm,clipString);
    		int nChars;
    		for(nChars = 0; nChars < text.length(); nChars++) {
    		    totalWidth += fm.charWidth(text.charAt(nChars));
    		    if (totalWidth > availTextWidth) {
    			break;
    		    }
    		}
    		text = text.substring(0, nChars) + clipString;
    		textR.width = computeStringWidth(fm,text);
    	    }
    	}
    */


    	/* Compute textR.x,y given the verticalTextPosition and
    	 * horizontalTextPosition properties
    	 */

    	if (verticalTextPosition == SwingUtilities.TOP) {
    	    if (horizontalTextPosition != SwingUtilities.CENTER) {
        		textR.y = 0;
    	    }
    	    else {
        		textR.y = -(textR.height + gap);
    	    }
    	}
    	else if (verticalTextPosition == SwingUtilities.CENTER) {
    	    textR.y = (iconR.height / 2) - (textR.height / 2);
    	}
    	else { // (verticalTextPosition == SwingUtilities.BOTTOM)
    	    if (horizontalTextPosition != SwingUtilities.CENTER) {
        		textR.y = iconR.height - textR.height;
    	    }
    	    else {
        		textR.y = (iconR.height + gap);
    	    }
    	}

    	if (horizontalTextPosition == SwingUtilities.LEFT) {
    	    textR.x = -(textR.width + gap);
    	}
    	else if (horizontalTextPosition == SwingUtilities.CENTER) {
    	    textR.x = (iconR.width / 2) - (textR.width / 2);
    	}
    	else { // (verticalTextPosition == SwingUtilities.RIGHT)
    	    textR.x = (iconR.width + gap);
    	}

    	/* labelR is the rectangle that contains iconR and textR.
    	 * Move it to its proper position given the labelAlignment
    	 * properties.
    	 */

    	Rectangle labelR = iconR.union(textR);
    	int dx, dy;

    	if (verticalAlignment == SwingUtilities.TOP) {
    	    dy = viewR.y - labelR.y;
    	}
    	else if (verticalAlignment == SwingUtilities.CENTER) {
    	    dy = (viewR.y + (viewR.height / 2)) - (labelR.y + (labelR.height / 2));
    	}
    	else { // (verticalAlignment == SwingUtilities.BOTTOM)
    	    dy = (viewR.y + viewR.height) - (labelR.y + labelR.height);
    	}

    	if (horizontalAlignment == SwingUtilities.LEFT) {
    	    dx = viewR.x - labelR.x;
    	}
    	else if (horizontalAlignment == SwingUtilities.CENTER) {
    	    dx = (viewR.x + (viewR.width / 2)) - (labelR.x + (labelR.width / 2));
    	}
    	else { // (horizontalAlignment == SwingUtilities.RIGHT)
    	    dx = (viewR.x + viewR.width) - (labelR.x + labelR.width);
    	}

    	/* Translate textR and glypyR by dx,dy.
    	 */
    	textR.x += dx;
    	textR.y += dy;

    	iconR.x += dx;
    	iconR.y += dy;

    	/* NOTE: calculate string offsets based on the string width and
    	 * horizontal alignment
    	 */
    	computeOffset(textR, horizontalAlignment, widthArray, offsetArray);

        //Debug.println("layoutCompound: " + text + " " + textR);
    	return text;
        }

    	final void computeOffset(Rectangle textR, int horizontalAlignment, int[] widthA, int[] offsetA) {
    	    for (int i = 0; i < widthA.length; i++) {
    	        if (SwingConstants.LEFT == horizontalAlignment) {
    	            offsetA[i] = textR.x;
    	        }
    	        else if (SwingConstants.RIGHT == horizontalAlignment) {
    	            offsetA[i] = textR.x + textR.width - widthA[i];
    	        }
    	        else if (SwingConstants.CENTER == horizontalAlignment) {
    	            offsetA[i] = textR.x + (int)((textR.width - widthA[i]) * 0.5);
    	        }
    	    }
    	}

    	final int findAccChar(Vector strV, char c) {
    	    for (int i = 0; i < strV.size(); i++) {
    	        String s = (String)strV.elementAt(i);
    	        if (s.indexOf(c) != -1) {
    	            return i;
    	        }
    	    }
    	    return 0;
    	}
}
