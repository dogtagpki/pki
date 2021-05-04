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
package com.netscape.admin.certsrv.config;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.ResourceBundle;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ListSelectionModel;

import com.netscape.admin.certsrv.CMSAdminResources;
import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.CMSBaseResourceModel;
import com.netscape.admin.certsrv.EAdminException;
import com.netscape.admin.certsrv.connection.AdminConnection;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.JButtonFactory;

/**
 * Plugin Selection Dialog
 *
 * @author Jack Pan-chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
public class PluginSelectionDialog extends JDialog
    implements ActionListener, MouseListener
{
    private static final long serialVersionUID = 1L;

    /*==========================================================
     * variables
     *==========================================================*/
    protected JFrame mParentFrame;
    protected AdminConnection mConnection;
    protected ResourceBundle mResource;
    protected ProfileListDataModel mDataModel;
    protected String mDestination;              //dest flag
    protected String mExtraDestination = null;              //dest flag

    private JScrollPane mScrollPane;
    protected JList<JLabel> mList;

    protected JButton mOK, mCancel, mHelp;
    protected String mPrefix;
    protected String mScope;
    protected String mInstanceScope;
    protected String mImageName;
    protected String mHelpToken;
	protected CMSPluginInstanceTab mPluginInstanceDialog;
	protected CMSBaseResourceModel mModel=null;

    public PluginSelectionDialog(
			String prefix,
			JFrame parent,
			AdminConnection conn,
			String dest)
	{
		this(	prefix,
				parent,
				conn,
				dest,
				null );
	}

    /*==========================================================
     * constructors
     *==========================================================*/
    public PluginSelectionDialog(
			String prefix,
			JFrame parent,
			AdminConnection conn,
			String dest,
			CMSPluginInstanceTab pluginType)
	{
        super(parent,true);
        mParentFrame = parent;
        mConnection = conn;
        mDestination = dest;
        mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
        mDataModel = new ProfileListDataModel();
        mPrefix = prefix;
		mPluginInstanceDialog = pluginType;

        setTitle(mResource.getString(mPrefix+"_TITLE"));
        setSize(360, 216);
        setLocationRelativeTo(parent);
        getRootPane().setDoubleBuffered(true);
    }

    public PluginSelectionDialog(
            String prefix,
            JFrame parent,
            AdminConnection conn,
            String dest, String extraDest,
            CMSPluginInstanceTab pluginType)
    {
        super(parent,true);
        mParentFrame = parent;
        mConnection = conn;
        mDestination = dest;
        mExtraDestination = extraDest;
        mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
        mDataModel = new ProfileListDataModel();
        mPrefix = prefix;
        mPluginInstanceDialog = pluginType;

        setTitle(mResource.getString(mPrefix+"_TITLE"));
        setSize(360, 216);
        setLocationRelativeTo(parent);
        getRootPane().setDoubleBuffered(true);
    }

    /*==========================================================
     * public methods
     *==========================================================*/

	public void setModel(CMSBaseResourceModel model)
	{
		mModel = model;
	}

    /**
     * show the windows
     * @param users list of current groups
     */
    public void showDialog() {

        mDataModel.clear();

        if(!update())
            return;
        refresh();
        setArrowButtons();
        this.show();
    }

    /*==========================================================
     * EVNET HANDLER METHODS
     *==========================================================*/

    //=== ACTIONLISTENER =====================
    public void actionPerformed(ActionEvent evt) {

		if (evt.getSource().equals(mOK)) {
            NameValuePairs response;
            try {
                response = getDefaultConfig();
            } catch (EAdminException e) {
                CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                    e.getMessage(), CMSAdminUtil.ERROR_MESSAGE);
                return;
            }
            Debug.println(response.toString());
            String id = mDataModel.elementAt(mList.getSelectedIndex()).getText();
            response.put(Constants.PR_POLICY_IMPL_NAME, id);

            CMSBaseConfigDialog dialog = null;
            if (mExtraDestination == null) {
                dialog = mPluginInstanceDialog.makeNewConfigDialog(
                  response, mParentFrame, mConnection, mDestination);
            } else  {
                dialog = mPluginInstanceDialog.makeNewConfigDialog(
                  response, mParentFrame, mConnection, mExtraDestination);
		    }

			dialog.setModel(mModel);
			dialog.setInstanceScope(mInstanceScope);

            dialog.showDialog(response,"");

            if(!dialog.isOK()) {
                this.dispose();
                return;
            }

            response = dialog.getData();
            dialog.getRuleName();

            Debug.println(response.toString());

			dialog.dispose();
            this.dispose();
        }


        if (evt.getSource().equals(mCancel)) {
            this.dispose();
        }
        if (evt.getSource().equals(mHelp)) {
            CMSAdminUtil.help(mHelpToken);
        }
    }

    //==== MOUSELISTENER ======================
    public void mouseClicked(MouseEvent e) {
        setArrowButtons();
    }

    public void mousePressed(MouseEvent e) {}
    public void mouseReleased(MouseEvent e) {
        setArrowButtons();
    }
    public void mouseEntered(MouseEvent e) {}
    public void mouseExited(MouseEvent e) {
        setArrowButtons();
    }

    protected void setDisplay() {
		Debug.println("*** PluginSelectionDialog.setDisplay() - 1");
        getContentPane().setLayout(new BorderLayout());
        JPanel center = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        center.setLayout(gb);

        //content panel
        JPanel content = makeContentPane();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        gb.setConstraints(content, gbc);
        center.add(content);

        //action panel
        JPanel action = makeActionPane();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gb.setConstraints(action, gbc);
        center.add(action);

        getContentPane().add("Center",center);
    }

    //create botton action panel
    private JPanel makeActionPane() {
        mOK = CMSAdminUtil.makeJButton(mResource, mPrefix, "OK", null, this);
        mCancel = CMSAdminUtil.makeJButton(mResource, mPrefix, "CANCEL", null, this);
        mHelp = CMSAdminUtil.makeJButton(mResource, mPrefix, "HELP", null, this);
        //JButton[] buttons = { mOK, mCancel, mHelp};
        JButton[] buttons = { mOK, mCancel};
        JButtonFactory.resize( buttons );
        return CMSAdminUtil.makeJButtonPanel( buttons, true);
    }

    private JPanel makeContentPane() {
		Debug.println("*** PluginSelectionDialog.makeContentPane() - 0");
        JPanel mListPanel = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
		Debug.println("*** PluginSelectionDialog.makeContentPane() - 1");
        mListPanel.setLayout(gb);
        //content.setBorder(CMSAdminUtil.makeEtchedBorder());

		Debug.println("*** PluginSelectionDialog.makeContentPane() - 2");
        //left side certificate table
        mList = CMSAdminUtil.makeJList(mDataModel,9);
		Debug.println("PluginSelectionDialog.makeContentPane() - making mList("+mList+")");
        mScrollPane = new JScrollPane(mList,
            JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
            JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        mList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION );
        mList.addMouseListener(this);
        mScrollPane.setBackground(Color.white);
        mScrollPane.setBorder(BorderFactory.createLoweredBevelBorder());

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        gb.setConstraints(mScrollPane, gbc);
        mListPanel.add(mScrollPane);

        return mListPanel;
    }


    //set arrow buttons
    private void setArrowButtons() {

        //enable and diable buttons accordingly
        //Debug.println("setArrowButtons() - "+mList.getSelectedIndex());

        if (mList.getSelectedIndex()< 0) {
            mOK.setEnabled(false);
            return;
        }

        mOK.setEnabled(true);
    }

    //refresh the table content
    private void refresh() {
        //mScrollPane.invalidate();
        //mScrollPane.validate();
        //repaint();
    }

    //=================================================
    // RETRIEVE INFO FROM SERVER SIDE
    //=================================================

    //save order information to the server
    protected boolean update() {

        NameValuePairs response;
        try {
            response = mConnection.search(mDestination, mScope,
                               new NameValuePairs());
        } catch (EAdminException e) {
            //display error dialog
            CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                e.getMessage(), CMSAdminUtil.ERROR_MESSAGE);
            return false;
        }

        Debug.println(response.toString());

        //parse the data
        String[] vals = new String[response.size()];
        int i=0;
        for (String name : response.keySet()) {
            vals[i++] = name.trim();
			Debug.println("PluginSelectionDialog::update() - adding '" + vals[i - 1] + "'");
        }

        CMSAdminUtil.bubbleSort(vals);

        for (int y=0; y< vals.length ; y++) {
			try {
            mDataModel.addElement(new JLabel(vals[y],
              CMSAdminUtil.getImage(mImageName), JLabel.LEFT));
			}
			catch (Exception ex) {
				Debug.println("PluginSelectionDialog could not get image for '"+
					mImageName+"'. Adding without image");
            mDataModel.addElement(new JLabel(vals[y],
              JLabel.LEFT));
			}
        }

        return true;
    }

    //this returns the default configuration
    protected NameValuePairs getDefaultConfig() throws EAdminException {
        String id = mDataModel.elementAt(mList.getSelectedIndex()).getText();
        NameValuePairs response;
        response = mConnection.read(mDestination, mScope, id,
          new NameValuePairs());

        Debug.println(response.toString());

        return response;
    }

}
