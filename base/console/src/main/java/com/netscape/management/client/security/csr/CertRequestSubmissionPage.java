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
package com.netscape.management.client.security.csr;
//package com.netscape.management.client.keycert;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import javax.swing.*;
import javax.swing.event.*;
import java.io.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;


class CertRequestSubmissionPage extends JPanel implements IUIPage, SuiConstants, ActionListener/*, DocumentListener*/ {


    JButton m_cpToClipBoard, m_saveToFile;
    String _cert = "";
    ResourceSet resource = new ResourceSet("com.netscape.management.client.security.KeyCertWizardResource");
    Hashtable _sessionData;

    /*JRadioButton m_cpToClipBoard, m_saveToFile;
    JTextField m_filename = new JTextField();
    JButton m_browse;*/

    public void actionPerformed(ActionEvent e) {
        if (_sessionData.get("pkcs#10") != null) {
            _cert = (String)(_sessionData.get("pkcs#10"))+"\n";
        }

	if (e.getActionCommand().equals("COPY")) {
            JTextArea tmp = new JTextArea(_cert);
            tmp.selectAll();
            tmp.copy();
        } else if (e.getActionCommand().equals("SAVE")) {
	    JFileChooser jfchooser = new JFileChooser();
	    if (jfchooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION){
		try {
		    File f = jfchooser.getSelectedFile();

		    RandomAccessFile rf = new RandomAccessFile(f, "rw");
		    rf.writeBytes(_cert);
		    rf.close();
		} catch (Exception fileError) {
		    Debug.println("unable to save file to to local file system");
		}

	    }
	}
    }

    public String getPageName() {
	return resource.getString("CertRequestSubmissionPage", "pageTitle");
    }

    public Component getComponent() {
	return this;
    }

    public void addChangeListener(ChangeListener l) {}

    public void removeChangeListener(ChangeListener l) {}

    public boolean isPageValidated() {
	return true;
    }

    public IUIPage getNextPage() {
	return null;
    }
    public IUIPage getPreviousPage() {
	return null;
    }

    public String getHelpURL() {
	return "CertRequestSubmissionPage";
    }

    public int getRemainingPageCount() {
	return 0;
    }

    public CertRequestSubmissionPage(Hashtable sessionData) {
        super();
        setLayout(new GridBagLayout());
	_sessionData = sessionData;
        MultilineLabel _explain = new MultilineLabel(resource.getString("CertRequestSubmissionPage", "explain"));


        int y = 0;

        GridBagUtil.constrain(this, _explain,
                              0, y, 2, 1,
                              1.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.BOTH,
                              0, 0, DIFFERENT_COMPONENT_SPACE, 0);

	/*JPanel saveToFile = new JPanel();
	saveToFile.setLayout(new GridBagLayout());

        m_saveToFile    = new JRadioButton(resource.getString("CertRequestSubmissionPage", "saveToFileLabel"), false);
	GridBagUtil.constrain(saveToFile, m_saveToFile,
                              0, 0, 1, 1,
                              0.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.NONE,
                              0, 0, 0, 0);

	GridBagUtil.constrain(saveToFile, m_filename,
                              1, 0, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                              0, 0, 0, 0);

	m_browse = new JButton(resource.getString("CertRequestSubmitPage", "browseLabel"));
	GridBagUtil.constrain(saveToFile, m_browse,
                              2, 0, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.NONE,
                              0, 0, 0, 0);

        m_cpToClipBoard = new JRadioButton(resource.getString("CertRequestSubmissionPage", "cpToClipboardLabel"), false);
	
        GridBagUtil.constrain(this, saveToFile,
                              0, ++y, 2, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, 0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this, m_cpToClipBoard,
                              0, ++y, 2, 1,
                              1.0, 1.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, 0, 0, 0);*/

        m_cpToClipBoard = JButtonFactory.create(resource.getString("CertRequestSubmissionPage", "cpToClipboardLabel"), this, "COPY");
        m_cpToClipBoard.setToolTipText(resource.getString("CertRequestSubmissionPage", "cpToClipboard_tt"));
        m_saveToFile    = JButtonFactory.create(resource.getString("CertRequestSubmissionPage", "saveToFileLabel"), this, "SAVE");
        m_saveToFile.setToolTipText(resource.getString("CertRequestSubmissionPage", "saveToFile_tt"));
        JButtonFactory.resize(m_cpToClipBoard, m_saveToFile);

        JPanel manualButtonPane = new JPanel();
        manualButtonPane.setLayout(new BoxLayout(manualButtonPane, BoxLayout.X_AXIS));
        manualButtonPane.add(m_cpToClipBoard);
        manualButtonPane.add(Box.createHorizontalStrut(COMPONENT_SPACE));
        manualButtonPane.add(m_saveToFile);
        GridBagUtil.constrain(this, manualButtonPane,
                              0, ++y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                              0, DIFFERENT_COMPONENT_SPACE, DIFFERENT_COMPONENT_SPACE, 0);


        GridBagUtil.constrain(this, Box.createVerticalGlue(),
                              0, ++y, 2, 1,
                              1.0, 1.0,
                              GridBagConstraints.NORTH, GridBagConstraints.BOTH,
                              0, 0, 0, 0);
    }

    /*public static void main(String args[]) {
	CertRequestSubmissionPage submit = new CertRequestSubmissionPage(new Hashtable());
	JFrame f = new JFrame();
	f.getContentPane().add(submit);
	f.setSize(300,300);
	f.show();
    }*/
}


