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

package com.netscape.management.client.console;

import java.awt.*;
import java.util.*;
import javax.swing.*;
import javax.swing.event.*;
import com.netscape.management.nmclf.*;
import com.netscape.management.client.util.*;


/**
 * Displays a login dialog for Console.
 * The dialog contains three fields: username,
 * password, and login url.
 */
public class LoginDialog extends AbstractDialog implements SwingConstants,
SuiConstants {
    protected static String _resourcePrefix = "login";

    JComboBox _urlField;
    JTextField _useridField = new JTextField(22);
    JTextField _passwordField = new SuiPasswordField(22);

    int _x = -1;
    int _y = -1;

    /**
     * constructor
     *
     * @param parentFrame parent frame
     * @param userid user ID
     * @param url admin server url
     */
    public LoginDialog(Frame parentFrame, String userid, String initialURL, Vector recentURLs) {
        this(parentFrame, userid, initialURL, recentURLs,
                Console._resource_theme.getString(_resourcePrefix, "title"),
                "login");
    }

    /**
      * constructor which let the caller decides the title and specifies recently used urls
      *
      * @param parentFrame parent frame
      * @param userid User ID
      * @param urls vector of strings containing recently used URLs
      * @param title dialog title
      * @param resourcePrefix the resource file prefix
      */
    public LoginDialog(Frame parentFrame, String userid, String defaultURL, Vector recentURLs, String title, String resourcePrefix) {
        super(parentFrame, title, true, OK | CANCEL | HELP);
        _resourcePrefix = resourcePrefix;

		setOKButtonEnabled(false);
		_passwordField.getDocument().addDocumentListener(new EmptyFieldListener());

        _useridField.setText(userid);

	if(recentURLs != null) {
		_urlField = new JComboBox(recentURLs);
	}
	else {
		_urlField = new JComboBox();
	}
	_urlField.setEditable(true);
		
	if(_urlField.getItemCount() == 0)
		_urlField.addItem("");		// JFC bug: if no items in list, box size too big

	if(defaultURL != null) {
		_urlField.setSelectedItem(defaultURL);
	}
	else {
		_urlField.setSelectedIndex(0);	// select first item in list
	}
		
        createDialogPanel();
        setMinimumSize(getPreferredSize());
        setResizable(true);
    }
	
	
	class EmptyFieldListener implements DocumentListener
	{
		public void insertUpdate(DocumentEvent e)
		{
		    stateChanged();
		}
		
		public void changedUpdate(DocumentEvent e)
		{
		    stateChanged();
		}
		
		public void removeUpdate(DocumentEvent e)
		{
		    stateChanged();
		}
				
		void stateChanged()
		{
			setOKButtonEnabled(_passwordField.getText().trim().length() > 0);
		}
	}
	
    /**
      * set the initialize starting location.
      *
      * @param x x position
      * @param y y position
      */
    public void setInitialLocation(int x, int y) {
        _x = x;
        _y = y;
    }

    /**
      * create the actual dialog
      */
    protected void createDialogPanel() {
        JPanel panel = new JPanel();
        GridBagLayout gridbag = new GridBagLayout();
        panel.setLayout(gridbag);
        commonPanelLayout(panel);
        setPanel(panel);
    }

    /**
      * layout the dialog content. It cannot be overwrite by the subclass of login dialog.
      *
      * @param panel dialog panel
      */

    protected void commonPanelLayout(JPanel panel) {
        JLabel usernameLabel = new JLabel(Console._resource.getString(_resourcePrefix, "username"));
        usernameLabel.setLabelFor(_useridField);
        GridBagUtil.constrain(panel, usernameLabel, 0,
                              GridBagConstraints.RELATIVE, 1, 1, 0.0, 0.0,
                              GridBagConstraints.EAST, GridBagConstraints.NONE, 0,
                              0, 0, DIFFERENT_COMPONENT_SPACE);
        
        GridBagUtil.constrain(panel, _useridField, 1,
                              GridBagConstraints.RELATIVE, 1, 1, 1.0, 0.0,
                              GridBagConstraints.NORTHWEST,
                              GridBagConstraints.HORIZONTAL, 0, 0, 0, 0);

		JLabel passwordLabel = new JLabel(Console._resource.getString(_resourcePrefix, "password"));
        passwordLabel.setLabelFor(_passwordField);
        GridBagUtil.constrain(panel, passwordLabel, 0,
                              GridBagConstraints.RELATIVE, 1, 1, 0.0, 0.0,
                              GridBagConstraints.EAST, GridBagConstraints.NONE,
                              COMPONENT_SPACE, 0, 0, DIFFERENT_COMPONENT_SPACE);
        
        GridBagUtil.constrain(panel, _passwordField, 1,
                              GridBagConstraints.RELATIVE, 1, 1, 1.0, 0.0,
                              GridBagConstraints.NORTHWEST,
                              GridBagConstraints.HORIZONTAL, COMPONENT_SPACE, 0, 0, 0);
        
        if (_useridField.getText().length() > 0)
            setFocusComponent(_passwordField);
		else
			setFocusComponent(_useridField);
        
        JLabel urlLabel = new JLabel(Console._resource.getString(_resourcePrefix, "url"));
        urlLabel.setLabelFor(_urlField);
        GridBagUtil.constrain(panel, urlLabel, 0,
                              GridBagConstraints.RELATIVE, 1, 1, 0.0, 0.0,
                              GridBagConstraints.EAST, GridBagConstraints.NONE,
                              COMPONENT_SPACE, 0, 0, DIFFERENT_COMPONENT_SPACE);
        
        GridBagUtil.constrain(panel, _urlField, 1,
                              GridBagConstraints.RELATIVE, 1, 1, 1.0, 0.0,
                              GridBagConstraints.NORTHWEST,
                              GridBagConstraints.HORIZONTAL, COMPONENT_SPACE, 0, 0, 0);
    }

    /**
      * return the admin server URL
      *
      * @return Netscape Admin Server URL
      */
    public String getURL() {
		Object result;
		result = _urlField.getSelectedItem();
		if(result == null)
			return "";
		if(!((String)result).startsWith("http://") && !((String)result).startsWith("https://"))
			result = "http://" + result;
		return (String)result;
    }

    /**
      * return the login user name or full dn
      *
      * @return return the user id field value
      */
    public String getUsername() {
        return _useridField.getText();
    }

    /**
      * return the user password
      *
      * @return return the password field value
      */
    public String getPassword() {
        return _passwordField.getText();
    }

    /**
      * set the dialog location
      *
      * @param parentFrame parent frame
      */
    protected void setDialogLocation(Frame parentFrame) {
        if (_x > 0 && _y > 0)
            setLocation(_x, _y);
        else
            setLocationRelativeTo(parentFrame);
    }

    protected void okInvoked() {
        Debug.println(Debug.TYPE_RSPTIME, "Login user ...");
        super.okInvoked();
    }

    /**
      * invoke help
      */
    protected void helpInvoked() {
        /* Display a help dialog */
        String helpMsg = Console._resource.getString("login", "help");
        if (helpMsg.length()>0) {
            JOptionPane.showMessageDialog(
                    SplashScreen.getInstance(), helpMsg,
                    Console._resource.getString("login","helptitle"),
                    JOptionPane.INFORMATION_MESSAGE);
            ModalDialogUtil.sleep();
        }
    }
}
