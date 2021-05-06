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

import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.MouseEvent;
import java.util.Hashtable;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.ScrollPaneConstants;

import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.CMSBaseResourceModel;
import com.netscape.admin.certsrv.EAdminException;
import com.netscape.admin.certsrv.LabelCellRenderer;
import com.netscape.admin.certsrv.connection.AdminConnection;
import com.netscape.admin.certsrv.ug.CMSBaseUGTab;
import com.netscape.certsrv.common.DestDef;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.JButtonFactory;

/**
 * Jobs Instances Management Tab
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
public class JobsImplTab extends CMSBaseUGTab {

    /*==========================================================
     * variables
     *==========================================================*/
    private static final String IMPL_NAME = JobsImplDataModel.IMPL_NAME;
    private static final String IMPL_CLASS = JobsImplDataModel.IMPL_CLASS;
    private static final String IMPL_DESC = JobsImplDataModel.IMPL_DESC;

    private static final String PANEL_NAME = "JOBSIMPL";

    private AdminConnection mConnection;
    private String mDestination;

    protected JScrollPane mScrollPane;
    protected JTable mTable;                    //table
    protected JobsImplDataModel mDataModel;   //table model
    protected JobsRegisterDialog mEditor=null;      //keep single copy
    protected ViewDialog mViewer=null;      //keep single copy

    protected JButton mRefresh, mAdd, mDelete, mView, mHelp;
    private final static String HELPINDEX = "jobsscheduler-certsrv-jobplugin-help";

    /*==========================================================
     * constructors
     *==========================================================*/
    public JobsImplTab(CMSBaseResourceModel model) {
        super(PANEL_NAME, model);
        mConnection = model.getServerInfo().getAdmin();
        mDataModel = new JobsImplDataModel();
        mDestination = DestDef.DEST_JOBS_ADMIN;
		mHelpToken = HELPINDEX;
    }

    /*==========================================================
     * public methods
     *==========================================================*/


    /*==========================================================
     * EVNET HANDLER METHODS
     *==========================================================*/

    //=== ACTIONLISTENER =====================
    public void actionPerformed(ActionEvent e) {
        if (e.getSource().equals(mRefresh)) {
            refresh();
        }
        if (e.getSource().equals(mAdd)) {
            if (mEditor==null)
                mEditor = new JobsRegisterDialog(mModel.getFrame(),
                  mConnection);
            mEditor.showDialog(mDestination, ScopeDef.SC_JOBS_IMPLS);
            refresh();
        }
        if (e.getSource().equals(mDelete)) {
            Debug.println("Delete");
            if(mTable.getSelectedRow()< 0)
                return;
            int i = showConfirmDialog("DELETE");
            if (i == JOptionPane.YES_OPTION) {
                delete();
                Debug.println("Deleted");
            }
        }
        if (e.getSource().equals(mView)) {
            Debug.println("View");
            if(mTable.getSelectedRow()< 0)
                return;
            NameValuePairs obj = (NameValuePairs)
                    mDataModel.getObjectValueAt(mTable.getSelectedRow());
            if (mViewer==null)
                mViewer = new ViewDialog(mModel.getFrame());
            mViewer.showDialog(obj.get(IMPL_NAME),
                               obj.get(IMPL_CLASS),
                               obj.get(IMPL_DESC));
        }
        if (e.getSource().equals(mHelp)) {
            helpCallback();
        }
    }

    //==== MOUSELISTENER ======================
    public void mouseClicked(MouseEvent e) {
        setButtons();
    }

    public void mouseReleased(MouseEvent e) {
        setButtons();
    }

    /*==========================================================
     * protected methods
     *==========================================================*/
    public void refresh() {

        mDataModel.removeAllRows();
        update();

        setButtons();
        mTable.invalidate();
        mTable.validate();
        mTable.repaint(1);
    }

    /**
     * create the user action button panel
     */
    protected JPanel createButtonPanel() {
        //edit, add, delete, help buttons required
        //actionlister to this object
        mAdd = makeJButton("ADD");
        mDelete = makeJButton("DELETE");
        mView = makeJButton("VIEW");
        JButton[] buttons = {mAdd, mDelete, mView};
        JButtonFactory.resize( buttons );
        return CMSAdminUtil.makeJButtonVPanel( buttons );
    }

    protected JPanel createActionPanel() {
        //edit, add, delete, help buttons required
        //actionlister to this object
        mRefresh = makeJButton("REFRESH");
        mHelp = makeJButton("HELP");
        //JButton[] buttons = { mRefresh, mHelp };
        JButton[] buttons = { mRefresh };
        return makeJButtonPanel(buttons, true);
    }

    protected JPanel createListPanel() {
        mListPanel = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        mListPanel.setLayout(gb);

        //center table
        mTable = new JTable(mDataModel);
        mScrollPane = new JScrollPane(mTable);
        //mScrollPane.setBorder(CMSAdminUtil.makeTitledBorder(mResource,PANEL_NAME,"USERS"));
        mScrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        mScrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        mTable.setAutoscrolls(true);
        mTable.doLayout();
        mTable.getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        mTable.getSelectionModel().addListSelectionListener(this);
        mScrollPane.setBackground(Color.white);
        mTable.addMouseListener(this);
        setLabelCellRenderer(mTable,0);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTH;
      gbc.fill = GridBagConstraints.BOTH;
        gbc.gridwidth = 1;
        gbc.weightx = 1.0;
        gbc.insets = EMPTY_INSETS;
        gb.setConstraints(mScrollPane, gbc);
        mListPanel.add(mScrollPane);

        JPanel buttonPanel = createButtonPanel();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weightx = 0.0;
        gbc.weighty = 1.0;
        gbc.insets = EMPTY_INSETS;
        gb.setConstraints(buttonPanel, gbc);
        mListPanel.add(buttonPanel);

        refresh();

        return mListPanel;
    }

    //Set the first column's cellrender as label cell
    protected void setLabelCellRenderer(JTable table, int index) {
        table.getColumnModel().getColumn(index).setCellRenderer(new LabelCellRenderer(new JLabel()));
    }


    //set buttons
    private void setButtons() {

        //enable and diable buttons accordingly
        //Debug.println("setButtons() - "+mTable.getSelectedRow());
        //Debug.println("setButtons() - "+mTable.getSelectionModel().isSelectionEmpty());
        if (mTable.getSelectionModel().isSelectionEmpty()) {
            mDelete.setEnabled(false);
            mView.setEnabled(false);
            return;
        }

        if(mDataModel.getRowCount()<=0) {
            mDelete.setEnabled(false);
            mView.setEnabled(false);
            return;
        }

        mDelete.setEnabled(true);
        mView.setEnabled(true);

    }

    //=============================================
    // SEND REQUESTS TO THE SERVER SIDE
    //=============================================
    private void update() {
        //send request and parse data

        mModel.progressStart();
        NameValuePairs response;
        try {
            response = mConnection.search(mDestination,
                               ScopeDef.SC_JOBS_IMPLS,
                               new NameValuePairs());
        } catch (EAdminException e) {
            //display error dialog
            showErrorDialog(e.getMessage());
            mModel.progressStop();
            return;
        }

        Debug.println(response.toString());

        //parse the data
        int i=0;
        String[] vals = new String[response.size()];
        Hashtable<String, NameValuePairs> data = new Hashtable<String, NameValuePairs>();
        for (String entry : response.keySet()) {
            entry = entry.trim();
            String value = response.get(entry);
			Debug.println("entry= "+entry);
			Debug.println("value= " + value);
            int x = value.indexOf(",");
			Debug.println("x = " + x);
            NameValuePairs obj = new NameValuePairs();
            obj.put(IMPL_NAME, entry);
            vals[i++]= entry ;
			if (x != -1) {
		obj.put(IMPL_CLASS, value.substring(0, x));
		obj.put(IMPL_DESC, value.substring(x + 1));
			}
			else {
				obj.put(IMPL_CLASS, value);
			}
            data.put(entry,obj);
        }

        CMSAdminUtil.bubbleSort(vals);

        for (int y=0; y< vals.length ; y++) {
            mDataModel.processData(data.get(vals[y]));
        }

        data.clear();

        if (mDataModel.getRowCount() >0)
            mTable.setRowSelectionInterval(0,0);

        mModel.progressStop();
    }

    private void delete() {
        //get entry name
        mModel.progressStart();
        NameValuePairs obj = (NameValuePairs)
            mDataModel.getObjectValueAt(mTable.getSelectedRow());

        //send comment to server for the removal of user
        try {
            mConnection.delete(mDestination,
                               ScopeDef.SC_JOBS_IMPLS,
                               obj.get(IMPL_NAME));
        } catch (EAdminException e) {
            //display error dialog
            showErrorDialog(e.getMessage());
            mModel.progressStop();
            return;
        }
        mModel.progressStop();
        //send comment to server and refetch the content
        refresh();
    }

}
