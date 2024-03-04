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
import javax.swing.table.*;
import java.util.*;
import com.netscape.management.nmclf.*;

/**
 * Displays a list of tasks in table format
 */
public class TaskDetailArea extends SuiTable
{
    StatusDataModel myModel;
    
    /**
     * Constructs a new Task Detail Area (a 3-column table)with no horizontal
     * and vertical lines
     */
    public TaskDetailArea()
    {
        super();
        myModel = new StatusDataModel();
        setModel(myModel);
        setShowHorizontalLines(false);
        setShowVerticalLines(false);       
        setColumnWidth(0, 250);
        setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
    }
    
    /**
     * Sets the status of the specified row to the
     * specified status
     *
     * @param status the text value of the status
     * @param row the row number
     */
    public void setStatus(String status, int row)
    {
        myModel.setValueAt(status, row, 1);
    }
    
    /**
     * Gets the status of the specified row
     * 
     * @param row the row number
     * @return the status of the specified row
     */
    public String getStatus(int row)
    {
        return (String)myModel.getValueAt(row, 0);
    }
    
    /**
     * Sets the task of the specified row to 
     * the specified task
     *
     * @param task the task text
     * @param row the row number
     */
    public void setTask(String task, int row)
    {
        myModel.setValueAt(task, row, 0);
    }
    
    /** 
     * Sets the elapsed time of the specified row to 
     * the specified elapsed time
     *
     * @param elapsedTime the new elapsed time
     * @param row the row number
     */
    public void setElapsedTime(String elapsedTime, int row)
    {
        myModel.setValueAt(elapsedTime, row, 2);
    }
    
    /**
     * Gets the elapsed time of the specified row
     *
     * @param row the row number
     * @return the elapsed time of the specified row
     */
    public String getElapsedTime(int row)
    {
        return (String)myModel.getValueAt(row, 2);
    }
   
    /**
     * Gets the task information of the specified row
     *
     * @param row the row number
     * @return the task information of the specified row
     */
    public String getTask(int row)
    {
        return (String)myModel.getValueAt(row, 0);
    }
    
    /**
     * Adds a new task in the Task Detail Area
     *
     * @param task the complete information of the task including
     * the title, status, and time elapsed.
     * e.g. "Copying xyz file, Unknow, "
     */
    public void addNewTask(String task)
    {
        myModel.addTask(task);
    }
    
    /** 
     * Inner class StatusDataModel implementation.
     * Used to create abstract data model
     */
    class StatusDataModel extends AbstractTableModel
    {
        String columns[] = {"Tasks", "Status", "Time Elapsed"};
        Vector rows;
        
        /**
         * Creates a customized abstract table model made of two-dimensional vector
         */
        public StatusDataModel()
        {
            rows = new Vector();
        }
        
        /**
         * Returns number of columns in the table
         * 
         * @return length the number of columns in the table
         */
        public int getColumnCount()
        {
            return columns.length;
        }
        
        /**
         * Returns number of rows in the table
         *
         * @return size the number of rows in the table
         */
        public int getRowCount()
        {
            return rows.size();
        }
    
        /**
         * Returns the column name of the specified index
         *
         * @return columns[columnIndex] the name of the column
         */
        public String getColumnName(int columnIndex)
        {
            return columns[columnIndex];
        }
        
        /**
         * Returns the value of the specified row and column
         *
         * @return the object contained in the specified cell
         */
        public Object getValueAt(int row, int column)
        {
            return ((Vector)rows.elementAt(row)).elementAt(column);
        }
        
        /**
         * Sets the value of the specified row and column 
         * to the specified value
         *
         * @param value the value to be set
         * @param row the row number
         * @param column the column number
         */
        public void setValueAt(Object value, int row, int column)
        {
            ((Vector)rows.elementAt(row)).insertElementAt(value,column);
        }
        
        /**
         *
         * Adds a new task in the Task Detail Area
         */
        public void addTask(String task)
        {
            StringTokenizer subtask = new StringTokenizer(task, ",");
            rows.addElement(new Vector());
            if (subtask.hasMoreTokens())
            {
                ((Vector)rows.lastElement()).addElement(subtask.nextToken());
            }
            else
            {
                ((Vector)rows.lastElement()).addElement("");
            }
            
            if (subtask.hasMoreTokens())
            {
                ((Vector)rows.lastElement()).addElement(subtask.nextToken());
            }
            else
            {
                ((Vector)rows.lastElement()).addElement("");
            }
            
            if (subtask.hasMoreTokens())
            {
                ((Vector)rows.lastElement()).addElement(subtask.nextToken());
            }
            else
            {
                ((Vector)rows.lastElement()).addElement("");
            }
        }
    }
}