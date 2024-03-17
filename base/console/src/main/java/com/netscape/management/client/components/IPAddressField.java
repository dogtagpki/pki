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
import javax.swing.event.*;
import java.awt.*;
import java.awt.event.*;
import java.util.*;

/**
 * Used to get the IP Address input and validate it.
 * 
 * @author Andy Hakim
 * @author Thu Le
 */
public class IPAddressField extends JPanel 
{
    private IPByteField ipByteField1;
    private IPByteField ipByteField2;
    private IPByteField ipByteField3;
    private IPByteField ipByteField4;
    private JLabel dotLabel1;
    private JLabel dotLabel2;
    private JLabel dotLabel3;
    private Toolkit toolkit;
    protected EventListenerList listenerList = new EventListenerList();
    private IPAddressDocumentListener byteFieldListener = new IPAddressDocumentListener();
    
    /**
     * Construct a new IPAddressField initialized with the the default blank IP Address.
     *
     * The IPAddressField extends JPanel and contains ipByteFields and labels
     * Each ipByteField has a focusListener to check whether the IP value is
     * valid when it looses its focus.
     */
    public IPAddressField()
    {
		this(" . . . ");
    }
   
    /**
     * Construct a new IPAddressField initialized with the specified IP Address.
     *
     * The IPAddressField extends JPanel and contains ipByteFields and labels.
     * Each ipByteField has a focusListener to check whether the IP value is
     * valid when it looses its focus.
     *
     * @param IPAddress To set the specified IP Address.
     */
    public IPAddressField(String ipAddress)
    {
        super();
        setLayout(new FlowLayout(FlowLayout.LEFT, 0,0));
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel,BoxLayout.X_AXIS));
        panel.setBackground(UIManager.getColor("TextField.background"));
        panel.setBorder(UIManager.getBorder("TextField.border"));
        
        toolkit = Toolkit.getDefaultToolkit();
         
        StringTokenizer inputAddress = new StringTokenizer(ipAddress,".");
        FocusListener focusListener = new IPByteFieldFocusListener();
        
        ipByteField1 = new IPByteField(inputAddress.nextToken());
        ipByteField1.addFocusListener(focusListener);
		ipByteField1.getDocument().addDocumentListener(byteFieldListener);
        panel.add(ipByteField1);
        dotLabel1 = new JLabel(".");
		dotLabel1.setOpaque(true);
		dotLabel1.setBorder(BorderFactory.createEmptyBorder(0, 1, 0, 1));
        panel.add(dotLabel1);  
        
        ipByteField2 = new IPByteField(inputAddress.nextToken());
        ipByteField2.addFocusListener(focusListener);
		ipByteField2.getDocument().addDocumentListener(byteFieldListener);
        panel.add(ipByteField2);
        dotLabel2 = new JLabel(".");
		dotLabel2.setOpaque(true);
		dotLabel2.setBorder(BorderFactory.createEmptyBorder(0, 1, 0, 1));
        panel.add(dotLabel2); 
        
        ipByteField3 = new IPByteField(inputAddress.nextToken());
        ipByteField3.addFocusListener(focusListener);
		ipByteField3.getDocument().addDocumentListener(byteFieldListener);
        panel.add(ipByteField3);
        dotLabel3 = new JLabel(".");
		dotLabel3.setOpaque(true);
		dotLabel3.setBorder(BorderFactory.createEmptyBorder(0, 1, 0, 1));
        panel.add(dotLabel3); 
       
        ipByteField4 = new IPByteField(inputAddress.nextToken());
        ipByteField4.addFocusListener(focusListener);
		ipByteField4.getDocument().addDocumentListener(byteFieldListener);
        panel.add(ipByteField4);
        
        add(panel);
		setEnabled(true);
   }
   
    /**
     * Sets the ipByteFields values by extracting the specified IP Address
     *
     * @param ipAddress the IP Address value in String type
     */
    public void setIPAddress(String ipAddress)
    {
        if (ipAddress == null || ipAddress.length() == 0) {
            ipAddress = " . . . ";
        }
        StringTokenizer inputAddress = new StringTokenizer(ipAddress,".");
        if (inputAddress.hasMoreTokens())
            ipByteField1.setText(inputAddress.nextToken());
        if (inputAddress.hasMoreTokens())
            ipByteField2.setText(inputAddress.nextToken());
        if (inputAddress.hasMoreTokens())
            ipByteField3.setText(inputAddress.nextToken());
        if (inputAddress.hasMoreTokens())
            ipByteField4.setText(inputAddress.nextToken());
    }
    
     /**
     * Gets the IPAddress from the user inputs
     *
     * @return the IPAddress in the form of a string
     */
    public String getIPAddress()
    {
        if (ipByteField1.getText().equals("*"))
            return "*.*.*.*";
        else
            return (ipByteField1.getText() + "." + ipByteField2.getText() + "." 
                + ipByteField3.getText() + "." + ipByteField4.getText());
    }
    
	/**
	 * Checks to see if the field is empty.
	 * If any of the 4 byte fields do not contain a value,
	 * the field is considered to be empty.
	 * 
	 * @return true if all byte fields contain a value
	 */
	public boolean isEmpty()
	{
		if(ipByteField1.getText().length() > 0 &&
		   ipByteField2.getText().length() > 0 &&
		   ipByteField3.getText().length() > 0 &&
		   ipByteField4.getText().length() > 0)
		{
			return false;
		}
		return true;
	}
	
    /**
     * enable or disable use of wildcard (*) character
     */
    public void setWildcardAllowed(boolean state)
    {
        ipByteField1.setWildcardAllowed(state);
        ipByteField2.setWildcardAllowed(state);
        ipByteField3.setWildcardAllowed(state);
        ipByteField4.setWildcardAllowed(state);
    }
	
    /**
     * @return true if wildcards are allowed
     */
    public boolean isWildcardAllowed()
    {
        return ipByteField1.isWildcardAllowed();
    }

	private void validateField(IPByteField ipByteField)
    {
		int value = ipByteField.getValue();
		if (value > 255)
		{ 
				ipByteField.setValue(255);
		}
    }
	
    class IPByteFieldFocusListener extends FocusAdapter
    {
        public void focusLost(FocusEvent e)
        {
            validateField((IPByteField)e.getComponent());
        }
    } 
    
        
    class IPAddressDocumentListener implements DocumentListener
    {
        public void insertUpdate(DocumentEvent e)
        {
            IPAddressField.this.fireStateChanged();
        }
		
		public void changedUpdate(DocumentEvent e)
		{
            IPAddressField.this.fireStateChanged();
        }
		
        public void removeUpdate(DocumentEvent e)
        {
            IPAddressField.this.fireStateChanged();
        }
    }
    
	
    /**
     * Add a listener to the list that's notified each time a change
     * to the data model occurs.
     * 
     * @param l the ChangeListener
     */  
	public void addChangeListener(ChangeListener l) 
	{
    	listenerList.add(ChangeListener.class, l);
    }

    /**
     * Remove a listener from the list that's notified each time a 
     * change to the data model occurs.
     * @param l the ChangeListener
     */  
	public void removeChangeListener(ChangeListener l) 
	{
	    listenerList.remove(ChangeListener.class, l);
    }

    protected void fireStateChanged()
    {
    	Object[] listeners = listenerList.getListenerList();
	    ChangeEvent e = null;

		for (int i = listeners.length - 2; i >= 0; i -= 2) 
		{
			if (listeners[i] == ChangeListener.class) 
			{
				if (e == null) 
				{
		            e = new ChangeEvent(this);
		        }
		        ((ChangeListener)listeners[i+1]).stateChanged(e);
	        }	       
	    }
    }
	
	/**
	 * Enables or disables this component, depending on the value of the parameter b. 
	 * An enabled component can respond to user input and generate events. 
	 * Components are enabled initially by default.
	 */
	public void setEnabled(boolean b)
	{
		super.setEnabled(b);
		Color c = UIManager.getColor(b ? "TextField.background" : "control");
		ipByteField1.setEnabled(b);
		ipByteField2.setEnabled(b);
		ipByteField3.setEnabled(b);
		ipByteField4.setEnabled(b);
		ipByteField1.setBackground(c);
		ipByteField2.setBackground(c);
		ipByteField3.setBackground(c);
		ipByteField4.setBackground(c);
		dotLabel1.setBackground(c);
		dotLabel2.setBackground(c);
		dotLabel3.setBackground(c);
	}
}
