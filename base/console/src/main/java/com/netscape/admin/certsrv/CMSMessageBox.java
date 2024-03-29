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

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Frame;
import java.awt.Insets;
import java.awt.Label;
import java.util.ResourceBundle;

import javax.swing.JDialog;
import javax.swing.JFrame;

/**
    A basic implementation of the JDialog class.
    @deprecated The PKI console will be removed once there are CLI equivalents of desired console features.
**/

@Deprecated(since="10.14.0", forRemoval=true)
public class CMSMessageBox extends JDialog
{
    private Label message;
    protected ResourceBundle mResource;

    public CMSMessageBox(JFrame parent, String title, String messageString, int width) {
        super(parent, title, false);
        setSize( width, 100 );
        setResizable( false );
        setLocationRelativeTo(parent);

        message = new Label( messageString, Label.CENTER );
        getContentPane().add( message, BorderLayout.CENTER );
        setVisible(true);
    }

    public CMSMessageBox(JFrame parent, String panelName, String keyword) {
        super(parent, "Status", false);
        int width = 300;
        mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
        String messageString = mResource.getString(panelName+"_DIALOG_PROGRESS_"+keyword);

        setSize( width, 100 );
        setResizable( false );
        setLocationRelativeTo(parent);

        message = new Label( messageString, Label.CENTER );
        getContentPane().add( message, BorderLayout.CENTER );
        setVisible(true);
    }

	public CMSMessageBox(Frame parent)
	{
		super(parent);

		// This code is automatically generated by Visual Cafe when you add
		// components to the visual environment. It instantiates and initializes
		// the components. To modify the code, only use code syntax that matches
		// what Visual Cafe can generate, or Visual Cafe may be unable to back
		// parse your Java file into its visual environment.
		//{{INIT_CONTROLS
		getContentPane().setLayout(null);
		setSize(405,305);
		setVisible(false);
		label1.setText("text");
		getContentPane().add(label1);
		label1.setBounds(96,96,206,52);
		//}}
	}

	public CMSMessageBox()
	{
		this((Frame)null);
	}

	public CMSMessageBox(String sTitle)
	{
		this();
		setTitle(sTitle);
	}

	@Override
    public void setVisible(boolean b)
	{
		super.setVisible(b);
	}

	static public void main(String args[])
	{
		(new CMSMessageBox()).setVisible(true);
	}

	@Override
    public void addNotify()
	{
		// Record the size of the window prior to calling parents addNotify.
		Dimension size = getSize();

		super.addNotify();

		if (frameSizeAdjusted)
			return;
		frameSizeAdjusted = true;

		// Adjust size of frame according to the insets
		Insets insets = getInsets();
		setSize(insets.left + insets.right + size.width, insets.top + insets.bottom + size.height);
	}

	// Used by addNotify
	boolean frameSizeAdjusted = false;

	//{{DECLARE_CONTROLS
	java.awt.Label label1 = new java.awt.Label();
	//}}

}


