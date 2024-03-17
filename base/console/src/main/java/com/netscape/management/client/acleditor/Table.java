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
package com.netscape.management.client.acleditor;

import javax.swing.JTable;
import javax.swing.JScrollPane;
import javax.swing.ScrollPaneConstants;
import java.awt.Rectangle;
import java.awt.Graphics;
import java.awt.Dimension;
import java.awt.Color;
import java.awt.event.MouseListener;
import java.awt.event.MouseMotionListener;
import java.awt.event.MouseEvent;

import java.util.Vector;

/**
 * JTable component for the ACLeditor.
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.2 8/28/97
 */

public class Table extends JScrollPane implements MouseListener,
MouseMotionListener {
    protected DataModelAdapter data = null;
    protected JTable table = null;
    protected Vector selectionListeners = new Vector();
    protected boolean mouseOverFocusEnabled = false;

    protected int selection = -1;
    protected int focusRow = -1;
    protected int focusCol = -1;

    public Table(DataModelAdapter dma) {
        table = new CustomJTable(data = dma);

        if (data instanceof SelectionListener)
            addSelectionListener((SelectionListener) data);

        table.setColumnSelectionAllowed(false);
        table.addMouseListener(this);
        table.addMouseMotionListener(this);
        table.getTableHeader().setReorderingAllowed(false);

        setVerticalScrollBarPolicy(
                ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        setViewport(createViewport());
        setViewportView(table);
        if (data.getHeaderVisible())
            setColumnHeaderView(table.getTableHeader());
    }

    protected DataModelAdapter getDataModelAdapter() {
        return data;
    }
    protected JTable getJTable() {
        return table;
    }

    protected int getRowCount() {
        return data.getRowCount();
    }

    protected void setMouseOverFocusEnabled() {
        mouseOverFocusEnabled = true;
    }

    protected void resizeAndRepaint() {
        ((CustomJTable) table).doResize();
    }

    protected void addRow() {
        data.addRow(table.getSelectedRow());
        resizeAndRepaint();
    }

    protected void deleteRow() {
        int selection = table.getSelectedRow();

        table.clearSelection();
        data.deleteRow(selection);
        selectionNotifyAll(-1, -1, 0, new CallbackAction() {
                    public void callback(Object o) {
                        resizeAndRepaint();
                    }
                }
                );
    }

    protected void moveRow(boolean up) {
        data.moveRow(table.getSelectedRow(), up);
        resizeAndRepaint();
    }

    protected void addSelectionListener(SelectionListener sl) {
        selectionListeners.addElement(sl);
    }

    protected void removeSelectionListener(SelectionListener sl) {
        selectionListeners.removeElement(sl);
    }

    protected void selectionNotifyAll(int row, int col, int clickCount,
            CallbackAction cb) {
        for (int i = 0 ; i < selectionListeners.size(); i++)
            ((SelectionListener)(selectionListeners.elementAt(i))).
                    selectionNotify(row, col, clickCount, cb);
    }

    public void mouseClicked(MouseEvent e) {
        int row = table.rowAtPoint(e.getPoint());
        int col = table.columnAtPoint(e.getPoint());

        if ((row == -1) || (col == -1)) {
            selection = -1;
            table.clearSelection();
        } else
            selection = row;

        selectionNotifyAll(selection, col, e.getClickCount(),
                new CallbackAction() {
                    public void callback(Object o) {
                        resizeAndRepaint();
                    }
                }
                );
    }

    public void mouseEntered(MouseEvent e) {}
    public void mousePressed(MouseEvent e) {}
    public void mouseReleased(MouseEvent e) {}
    public void mouseDragged(MouseEvent e) {}

    public void mouseExited(MouseEvent e) {
        if (!mouseOverFocusEnabled || !data.isFocusEnabled())
            return;

        if ((focusRow == -1) || (focusCol == -1))
            return;

        drawCellFocus(focusRow, focusCol, false);
        focusRow = focusCol = -1;
    }

    public void mouseMoved(MouseEvent e) {
        // DT 4/16/98 How's this for quick and dirty!

        if (!mouseOverFocusEnabled || !data.isFocusEnabled())
            return;

        int row = table.rowAtPoint(e.getPoint());
        int col = table.columnAtPoint(e.getPoint());

        if ((row == -1) || (col == -1)) {
            drawCellFocus(focusRow, focusCol, false);
            focusRow = focusCol = -1;
            return;
        }

        if ((focusRow != row) || (focusCol != col))
            drawCellFocus(focusRow, focusCol, false);
        drawCellFocus(focusRow = row, focusCol = col, true);
    }

    protected void drawCellFocus(int row, int col, boolean focus) {
        if ((row == -1) || (col == -1))
            return;

        Rectangle r = table.getCellRect(row, col, false);
        Graphics g = table.getGraphics();

        if (focus) {
            g.setColor(Color.blue);
            g.draw3DRect(r.x, r.y, r.width - 1, r.height - 1, false);
        } else {
            if (table.isCellSelected(row, col))
                g.setColor(table.getSelectionBackground());
            else
                g.setColor(table.getBackground());
            g.drawRect(r.x, r.y, r.width - 1, r.height - 1);
        }
    }

    protected void setRealSize(Dimension d) {
        table.setPreferredSize(d);
        table.setMinimumSize(d);
        table.setMaximumSize(d);
    }
}
