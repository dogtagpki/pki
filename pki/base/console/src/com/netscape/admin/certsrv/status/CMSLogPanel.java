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
package com.netscape.admin.certsrv.status;

import java.awt.*;
import java.util.*;
import javax.swing.*;
import javax.swing.table.*;
import javax.swing.border.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.*;
import javax.swing.event.*;
import java.awt.event.*;
import com.netscape.management.client.*;
import com.netscape.management.client.util.*;

/**
 * Log Panel to be displayed at the right hand side
 * <pre>
 * Top Panel with filter input:
 *          Number of entries: default 25
 *          Source: default all
 *          Log Level: default warning
 * </pre>
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.status
 */
public abstract class CMSLogPanel extends CMSBasePanel
    implements IResourceSelectionListener, IRefreshTab, IRefreshTabPanel, MouseListener
{

    /*==========================================================
     * variables
     *==========================================================*/
    private static String PANELNAME = "LOGCONTENT";

    public static int DEFAULT_LOG_ENTRY = 25;

    protected JPanel mFilterPanel, mListPanel, mActionPanel;  //panels
    protected boolean mInit = false;    // true if this panel is initialized
    protected CMSBaseResourceModel mModel;
    protected LogDataModel mDataModel;  //table data model

    protected JScrollPane mScrollPane;
    protected JTable mTable;            //table
    protected JButton mView, mRefresh, mHelp;  //action buttons
    protected JTextField mNoRecord;
    protected JComboBox mSource, mLevel, mFile;
    protected String mHelpToken;
    protected LogEntryViewDialog mViewer;

    /*==========================================================
     * constructors
     *==========================================================*/
    public CMSLogPanel( CMSBaseResourceModel model,LogDataModel dataModel) {
        super(PANELNAME);
        model.addIResourceSelectionListener(this);
        mModel = model;
        mDataModel = dataModel;
    }

    /*==========================================================
	 * public methods
     *==========================================================*/

    /**
     * Actual construction of the panel
     */
    public void init() {
        setLayout(new BorderLayout());

        //======== filter panel ======================
 		mFilterPanel = createFilterPanel();
		add("North",mFilterPanel);

        //======== list panel ========================
		mListPanel = createListPanel();
		mListPanel.setBorder(new EmptyBorder(SEPARATED_COMPONENT_SPACE,
		        DIFFERENT_COMPONENT_SPACE - COMPONENT_SPACE,
		        COMPONENT_SPACE,
		        DIFFERENT_COMPONENT_SPACE - COMPONENT_SPACE));
		add("Center",mListPanel);

		//====== action panel ===========================
		mActionPanel = createActionPanel();
		add("South",mActionPanel);
		updateArchive();
		refresh();
    }

    //== IResourceListener ===

    public void select(IResourceObject parent, Object viewInstance) {
        if (!mInit) {
            init();
            mInit = true;
        }

        //refresh the screen
        invalidate();
        validate();
        repaint(1);
    }

    public boolean unselect(IResourceObject parent, Object viewInstance) {
        return true;
    }

    /*==========================================================
	 * EVNET HANDLER METHODS
     *==========================================================*/

    //=== ACTIONLISTENER =====================
    public void actionPerformed(ActionEvent e) {
        if (e.getSource().equals(mRefresh)) {
            Debug.println("AccessLogPanel: Refresh Log");
            refresh();
        }else if (e.getSource().equals(mView)) { 
            if (mDataModel.getRowCount() == 0) {
                refresh();
            } else {
                viewDetail();
            }
        }else if (e.getSource().equals(mHelp)) {
            CMSAdminUtil.help(mHelpToken);
        } else if (e.getSource().equals(mLevel) || e.getSource().equals(mSource)
                  || e.getSource().equals(mFile)) {
            Debug.println("AccessLogPanel: Changed Log Level or Source or File");
            refresh(); 
        }
    }

    public CMSBasePanel getSelectedTab() {
        return this;
    }

    //==== MOUSELISTENER ======================
    public void mouseClicked(MouseEvent e) {
        //Debug.println("CertRepositoryPanel: mouseClicked() -"+e.toString());
        
        //we track the double click action on the table entry - View op
        if(e.getClickCount() == 2) {
            //Debug.println("View Detail");
            viewDetail();
        }
    }
    
    public void mousePressed(MouseEvent e) { }
    public void mouseReleased(MouseEvent e) { }
    public void mouseEntered(MouseEvent e) { }
    public void mouseExited(MouseEvent e) { }
    
    /**
     * refresh the table data
     */
    public void refresh() {
        mDataModel.removeAllRows();
        Debug.println("CMSLogPanel: refresh()");

        update();

        mTable.invalidate();
        mTable.validate();
        mTable.repaint(1);
		mScrollPane.invalidate();
		mScrollPane.validate();
		mScrollPane.repaint(1);
        if (mDataModel.getRowCount() > 0) {
            mTable.setRowSelectionInterval(0,0);
        }
    }

    /*==========================================================
	 * protected methods
     *==========================================================*/
    
    /**
     * View the log entry in a dialog box
     * (no assumption of validity)
     */
    protected void viewDetail() {
        //check item selected
        if (mTable.getSelectedRow()>= 0) {
            if (mViewer == null) 
                mViewer = new LogEntryViewDialog(mModel.getFrame());
            mViewer.showDialog(
                (String)mDataModel.getValueAt(mTable.getSelectedRow(),0),
                (String)mDataModel.getValueAt(mTable.getSelectedRow(),1),
                (String)mDataModel.getValueAt(mTable.getSelectedRow(),2),
                (String)mDataModel.getValueAt(mTable.getSelectedRow(),3),
                ((JLabel)mDataModel.getValueAt(mTable.getSelectedRow(),4)).getText());
        }
    }


    /**
     * create action button panel
     */
    protected JPanel createActionPanel() {
        //actionlister to this object
        mView = makeJButton("VIEW");
        mRefresh = makeJButton("REFRESH");
        mHelp = makeJButton("HELP");
		JButton[] buttons = { mView,mRefresh,mHelp };
		return makeJButtonPanel(buttons,true,true);
    }

    /**
     * create log listing panel
     */
    protected JPanel createListPanel() {
		mListPanel = new JPanel();
		mListPanel.setLayout(new BorderLayout());

		//center table
		mTable = new JTable(mDataModel);
		mScrollPane = JTable.createScrollPaneForTable(mTable);
		mScrollPane.setHorizontalScrollBarPolicy(mScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		mScrollPane.setVerticalScrollBarPolicy(mScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
		mTable.setAutoscrolls(true);
		mTable.addMouseListener(this);
		//setColumnWidth(mTable);
		mTable.setAutoResizeMode(mTable.AUTO_RESIZE_OFF);
		setColumnWidth(mTable);
		mTable.getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		mListPanel.add("Center",mScrollPane);
        setLabelCellRenderer(mTable,4);
        mScrollPane.setBackground(Color.white);
		return mListPanel;
    }


    protected void setColumnWidth(JTable table) {
        int i = table.getColumnModel().getColumnCount();
		for (int x=0; x< i-1; x++) {
			TableColumn col = table.getColumnModel().getColumn(x);
			col.setMinWidth(50);
			col.setResizable( true );
		}
		TableColumn col = table.getColumnModel().getColumn(i-1);
		col.setMinWidth(400);
		col.setResizable( true );
	}
	
    /**
     * create filter criteria panel
     */
    protected JPanel createFilterPanel() {
        JPanel panel = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        panel.setBorder(makeTitledBorder("OPTIONS"));
        panel.setLayout(gb);

        //entry
        CMSAdminUtil.resetGBC(gbc);
        JLabel noRec = makeJLabel("NUMBERREC");
		mNoRecord = makeJTextField(10);
		mNoRecord.setText(Integer.toString(DEFAULT_LOG_ENTRY));
		addEntryField(panel, noRec, mNoRecord, gbc);

		//source and level
		CMSAdminUtil.resetGBC(gbc);
		JLabel label1 = makeJLabel("SOURCE");
		mSource = makeJComboBox("SOURCE");
		JLabel label2 = makeJLabel("LOGLEVEL");
		mLevel = makeJComboBox("LOGLEVEL");
		CMSAdminUtil.addEntryField(panel, label1, mSource, label2, mLevel, gbc);
                mLevel.addActionListener(this);
                mSource.addActionListener(this);
                

		//file
		CMSAdminUtil.resetGBC(gbc);
		gbc.gridheight = gbc.REMAINDER;
		JLabel label3 = makeJLabel("FILE");
		mFile = new JComboBox();
        CMSAdminUtil.addEntryField(panel, label3, mFile, gbc);
                mFile.addActionListener(this);

        return panel;
    }

    /**
     * retrieve log entries from the server side and
     * populate the data model.
     */
    protected abstract void update();

    /**
     * retrieve archieve log file listing from the server
     * side and poupulate the combobox
     */
    protected abstract void updateArchive();

  	//Set the first column's cellrender as label cell
	protected void setLabelCellRenderer(JTable table, int index) {
	    table.getColumnModel().getColumn(index).setCellRenderer(new LabelCellRenderer(new JLabel()));
	}

    //=== OVERWRITE DIALOG MESSAGE =====================

    protected void showMessageDialog(String keyword, int messageType ) {
        CMSAdminUtil.showMessageDialog(mModel.getFrame(), mResource, mPanelName, keyword, messageType);
    }

    protected void showMessageDialog(String keyword) {
        showMessageDialog(keyword, ERROR_MESSAGE);
    }

    protected int showConfirmDialog(String keyword, int messageType ) {
        return CMSAdminUtil.showConfirmDialog(mModel.getFrame(), mResource, mPanelName, keyword, messageType);
    }

    protected int showConfirmDialog(String keyword) {
        return showConfirmDialog(keyword, WARNING_MESSAGE);
    }

    protected void showErrorDialog(String message) {
        CMSAdminUtil.showErrorDialog(mModel.getFrame(), mResource, message, ERROR_MESSAGE);
    }


    private static void addEntryField(JPanel panel, JComponent label,
      JComponent field, GridBagConstraints gbc) {
        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.gridx = 0;
        gbc.anchor = gbc.EAST;
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,0,0);
        panel.add( label, gbc );

        gbc.gridx++;
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.NONE;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
      		                            0,DIFFERENT_COMPONENT_SPACE);
        panel.add( field, gbc );
    }
}
