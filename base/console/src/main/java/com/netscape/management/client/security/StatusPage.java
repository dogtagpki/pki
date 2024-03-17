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
package com.netscape.management.client.security;

import java.awt.*;
import javax.swing.*;
import javax.swing.event.*;
import com.netscape.management.client.components.*;
import com.netscape.management.client.security.csr.*;
import com.netscape.management.client.util.*;

class StatusPage extends JPanel implements IUIPage {


    IDataCollectionModel _sessionData;

    JEditorPane editorPane;

    public void setStatus(String text) {
	String type = "text/plain";
	if (text.indexOf("<html>") != -1) {
	    type = "text/html";
	}

	editorPane.setContentType(type);
	editorPane.setText(text);
    }

    public StatusPage(IDataCollectionModel sessionData) {
	super();
	_sessionData = sessionData;

	setLayout(new GridBagLayout());

	editorPane = new JEditorPane();
	JScrollPane scrollPane = new JScrollPane(editorPane, 
						 JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, 
						 JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
	GridBagUtil.constrain(this, scrollPane,
			      0, 0,  1, 1, 
			      1.0, 1.0,
			      GridBagConstraints.NORTH, GridBagConstraints.BOTH,
			      0, 0, 0, 0);
    }
	
    public String getPageName() {
	return "Status Page";
    }

    public Component getComponent() {
	return this;
    }

    public boolean isPageValidated() {
	return true;
    }


    public String getHelpURL() {
	System.out.println("not yet implemented");
	return "";
    }

    public void addChangeListener(ChangeListener l) {}
    public void removeChangeListener(ChangeListener l) {}
	
    public int getRemainingPageCount() {
	return 0;
    }

    public IUIPage getNextPage() {
	return null;
    }
    
    public IUIPage getPreviousPage() {
	return null;
    }
}
