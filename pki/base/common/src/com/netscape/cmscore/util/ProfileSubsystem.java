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
package com.netscape.cmscore.util;


import java.awt.Frame;
import java.awt.TextArea;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.Vector;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.table.AbstractTableModel;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;


/**
 * A class represents a internal subsystem. This subsystem
 * can be loaded into cert server kernel to perform
 * run time system profiling.
 * <P>
 * 
 * @author thomask
 * @version $Revision$, $Date$
 */
public class ProfileSubsystem extends Frame implements ISubsystem, Runnable {

    /**
     *
     */
    private static final long serialVersionUID = -7411549542009497317L;
    private String mId = null;
    private Thread mMonitoring = new Thread(this);
    private TextArea mTextArea = null;
    private JScrollPane mThreads = null;
    private JTable mThreadTable = null;
    private JButton mGC = null;
    private ThreadTableModel mThreadModel = null;

    /**
     * Constructs a certificate server.
     */
    public ProfileSubsystem() {
        super();
    }

    /**
     * Retrieves subsystem identifier.
     */
    public String getId() {
        return mId;
    }

    public void setId(String id) throws EBaseException {
        mId = id;
    }

    /**
     * Initializes this subsystem with the given 
     * configuration store.
     * It first initializes resident subsystems,
     * and it loads and initializes loadable
     * subsystem specified in the configuration
     * store.
     * <P>
     * Note that individual subsystem should be
     * initialized in a separated thread if
     * it has dependency on the initialization
     * of other subsystems.
     * <P>
     *
     * @param owner owner of this subsystem
     * @param config configuration store
     */
    public synchronized void init(ISubsystem owner, IConfigStore config)
        throws EBaseException {
        JTabbedPane tabPane = new JTabbedPane();

        // general panel
        JPanel pane = new JPanel();

        mTextArea = new TextArea();
        //    mTextArea.setSize(500, 180);
        //mGC = new JButton("GC"); 
        //  pane.setLayout(new GridLayout(2, 1));
        pane.add(mTextArea);
        //  pane.add(mGC);
        mTextArea.setEditable(false);
        tabPane.addTab("General", mTextArea);
        tabPane.setSelectedIndex(0);

        // thread panel
        mThreadModel = new ThreadTableModel();
        updateThreadPanel();
        mThreadTable = new JTable(mThreadModel);
        // table.setEditable(false);
        mThreads = JTable.createScrollPaneForTable(mThreadTable);
        tabPane.addTab("Threads", mThreads);

        mThreadTable.addMouseListener(new ThreadTableEvent(mThreadTable));

        add(tabPane);
        setSize(500, 200);
        setVisible(true);
        mMonitoring.start();
    }

    public void startup() throws EBaseException {
    }

    /**
     * Stops this system.
     */
    public synchronized void shutdown() {
    }

    /*
     * Returns the root configuration storage of this system.
     * <P>
     *
     * @return configuration store of this subsystem
     */
    public IConfigStore getConfigStore() {
        return null;
    }

    public void updateGeneralPanel() {
        Runtime.getRuntime().gc();
        String text = 
            "JDK VM Information " + "\n" +
            "Total Memory: " +  
            Runtime.getRuntime().totalMemory() + "\n" +
            "Used Memory: " +  
            (Runtime.getRuntime().totalMemory() - 
                Runtime.getRuntime().freeMemory()) + "\n" +
            "Free Memory: " +  
            Runtime.getRuntime().freeMemory() + "\n" +
            "Number of threads: " +  
            Thread.activeCount() + "\n";

        mTextArea.setText(text);
    }

    public void updateThreadPanel() {
        Thread currentThread = Thread.currentThread();
        Vector data = new Vector();
        Thread threads[] = new Thread[100];
        int numThreads = Thread.enumerate(threads);

        for (int i = 0; i < numThreads; i++) {
            Vector row = new Vector();

            row.addElement(threads[i].getName());
            row.addElement(threads[i].getThreadGroup().getName());
            row.addElement(Integer.toString(threads[i].getPriority()));
            if (currentThread.getName().equals(threads[i].getName())) {
                row.addElement("true");
            } else {
                row.addElement("false");
            }
            row.addElement(Boolean.toString(threads[i].isInterrupted()));
            row.addElement(Boolean.toString(threads[i].isDaemon()));
            data.addElement(row);
        }

        Vector colNames = new Vector();

        colNames.addElement("Name");
        colNames.addElement("Group");
        colNames.addElement("Priority");
        colNames.addElement("isCurrent");
        colNames.addElement("isInterrupted");
        colNames.addElement("isDaemon");
     
        mThreadModel.setInfo(data, colNames);
        if (mThreadTable != null) {
            mThreadTable.setModel(mThreadModel);
            mThreadTable.updateUI();
        }
    }

    public void run() {
        while (true) {
            // To get exact memory statistics
            try {
                updateGeneralPanel();
                updateThreadPanel();
                // update every second
                mMonitoring.sleep(1000);
            } catch (Exception e) {
            }
        }
    }
}


class ThreadTableModel extends AbstractTableModel { 
    /**
     *
     */
    private static final long serialVersionUID = -6977965542104110870L;
    Vector rowData;
    Vector columnNames;

    public ThreadTableModel() {
    }

    public void setInfo(Vector _rowData, Vector _columnNames) {
        rowData = _rowData;
        columnNames = _columnNames;
    }

    public String getColumnName(int column) { 
        return columnNames.elementAt(column).toString(); 
    } 

    public int getRowCount() { 
        return rowData.size(); 
    } 

    public int getColumnCount() { 
        return columnNames.size(); 
    } 

    public Object getValueAt(int row, int column) { 
        return ((Vector) rowData.elementAt(row)).elementAt(column); 
    } 

    public boolean isCellEditable(int row, int column) { 
        return false; 
    } 

    public void setValueAt(Object value, int row, int column) { 
        ((Vector) rowData.elementAt(row)).setElementAt(value, column); 
        fireTableCellUpdated(row, column); 
    }
}


class ThreadTableEvent extends MouseAdapter { 

    private JTable mThreadTable = null;

    public ThreadTableEvent(JTable table) {
        mThreadTable = table;
    }

    public void mouseClicked(MouseEvent e) { 
        if (e.getClickCount() == 2) { 
            int row = mThreadTable.getSelectedRow();

            if (row != -1) {
                String name = (String) mThreadTable.getValueAt(row, 0);
                JDialog dialog = new JDialog();
                JTextArea field = new JTextArea();
                JScrollPane pane = new JScrollPane(field);

                field.setEditable(false);

                // get stack trace 
                Thread threads[] = new Thread[100];
                int numThreads = Thread.enumerate(threads);

                ByteArrayOutputStream outArray = new ByteArrayOutputStream(); 

                for (int i = 0; i < numThreads; i++) {
                    if (!threads[i].getName().equals(name))
                        continue;
                    PrintStream err = System.err; 

                    System.setErr(new PrintStream(outArray)); 
                    threads[i].dumpStack();  // not working, print only current thread
                    System.setErr(err); 
                }

                String str = outArray.toString();

                field.setText(str);
                dialog.setTitle(name);
                dialog.setSize(500, 400);
                dialog.setVisible(true);

                dialog.setContentPane(pane);
                dialog.show();
            }
        } 
    }

}
