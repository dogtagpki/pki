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
import javax.swing.text.*; 
import java.text.NumberFormat;
import java.text.ParseException;
import java.util.Locale;

/**
 * This <B>IPByteField</B> class inherits JTextField and allows only numeric inputs
 * and a maximum of 3 digits.
 */
class IPByteField extends JTextField 
{   
    private Toolkit toolkit;
    private NumberFormat integerFormatter;
    private char wildcardCharacter = '*';
    private boolean isWildcardAllowed = false;
    
    /**
     * Constructs a new IPByteField with the default column is 4 and
     * intializes the default address.
     */
    public IPByteField()
    {
		this("");
    }
	
    /**
     * Constructs a new IPByteField with the default column is 4 and
     * intializes the specified address.
     *
     * @param address value to be displayed 
     */
    public IPByteField(String address)
    {
        super(3);
        toolkit = Toolkit.getDefaultToolkit();
        integerFormatter = NumberFormat.getNumberInstance(Locale.US);
        integerFormatter.setParseIntegerOnly(true);
        setText(address);
        
        setHorizontalAlignment(javax.swing.SwingConstants.RIGHT);
		setBorder(BorderFactory.createEmptyBorder(0, 3, 0, 3));
    }
    
    /**
     * Creates the default implementation of the model to be used. 
     *
     * @return the IPByteDocument model
     */
    protected Document createDefaultModel()
    {
        return new IPByteDocument();
    }
    
    /**
     * Gets the value of the IPByteField.
     *
     * @return retVal the integer value of the IPByteField
     */
    public int getValue() 
    {
        int retVal = 0;
        try
        {
            retVal = integerFormatter.parse(getText()).intValue();
        }
        catch (ParseException e) 
        {   
        }
        return retVal;
    }
    
    /**
     * Set the text to be displayed to value
     * 
     * @param value the value of the IP Address field
     */
	public void setValue(int value) 
	{
        setText(integerFormatter.format(value));
    }
    
    /**
     * enable or disable use of wildcard (*) character
     */
    public void setWildcardAllowed(boolean state)
    {
        isWildcardAllowed = state;
    }
    
    /**
     * @return true if wildcards are allowed
     */
    public boolean isWildcardAllowed()
    {
        return isWildcardAllowed;
    }
    
    class IPByteDocument extends PlainDocument
    {  
        /**
         * Inserts only numeric values and allows maximum of 3 digits
         * into the document.
         * 
         * @param offs the starting offset >=0
         * @param str the string to insert
         * @param a the attributes for the inserted content
         */
        public void insertString (int offs, String str, AttributeSet a)
                throws BadLocationException
        {   
            char[] source = str.toCharArray();
            char[] result = new char[source.length];
            int j = 0;
            int number = 0;
            for (int i = 0; i < source.length; i++)
            {
				char c = source[i];
                if(Character.isDigit(c))
				{
                    result[j++] = c;
				}
                else 
				if(c == wildcardCharacter)
                {
                    if(isWildcardAllowed)
                        result[j++] = c;
                }
                else 
				if(getLength() > 0 && (c == '.' || c == ' '))
                {
                    transferFocus();
                    break;
                }
            }

            if(getLength() < 3)
            {
                if(!IPByteField.this.getText().equals("*"))
                    super.insertString(offs,new String(result, 0, j), a);
            }
            
            if(getLength() >= 3)
            {
                IPByteField.this.transferFocus();
            }
        }
    }
}