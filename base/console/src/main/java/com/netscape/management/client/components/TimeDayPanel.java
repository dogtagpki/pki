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

import java.awt.*;
import java.util.*;
import java.text.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.event.*;
import javax.swing.border.*;
import javax.swing.table.*;
import com.netscape.management.client.util.*;

/**
 * Allows selection of a contigious selection of time across days of a week.  
 * Time can be selected in one hour blocks.
 * 
 * @author Andy Hakim
 */
public class TimeDayPanel extends JPanel implements UIConstants
{
    private static final ResourceSet i18n = new ResourceSet("com.netscape.management.client.components.components");
    private JTable timeTable;
    private Vector dayOfWeek = new Vector();
    private JLabel selectionLabel = new JLabel();
    private static int DAY_COLUMN_WIDTH = 90;
    private static int MAX_DAYS = 7;

    private static String i18n(String id) 
    {
        return i18n.getString("timeDayPanel", id);
    }
    
    /**
     * Constructs a TimeDayPanel with no initial time selection.
     */
    public TimeDayPanel()
    {
        for(int i = 1; i <= MAX_DAYS; i++)
        {
            dayOfWeek.addElement(i18n("day"+String.valueOf(i)));
        }
        GridBagLayout gbl = new GridBagLayout();
        setLayout(gbl);
        GridBagConstraints gbc = new GridBagConstraints();
        
        gbc.gridx = 0;       gbc.gridy = 0;
        gbc.gridwidth = 1;   gbc.gridheight = 2;
        gbc.weightx = 1.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        JComponent timeDayPanel = createTimeDayPanel();
        gbl.setConstraints(timeDayPanel, gbc);
        add(timeDayPanel);

        gbc.gridx = 1;       gbc.gridy = 0;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 0.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(35, COMPONENT_SPACE, 0, 0);
        JComponent buttonPanel = createButtonPanel();
        gbl.setConstraints(buttonPanel, gbc);
        add(buttonPanel);
        
        gbc.gridx = 1;       gbc.gridy = 1;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 0.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(15, COMPONENT_SPACE, 0, 0);
        JComponent legendPanel = createLegendPanel();
        gbl.setConstraints(legendPanel, gbc);
        add(legendPanel);

        gbc.gridx = 0;       gbc.gridy = 2;
        gbc.gridwidth = 2;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, DAY_COLUMN_WIDTH, 0, 0);
        gbl.setConstraints(selectionLabel, gbc);
        add(selectionLabel);        
    }
    
    protected JComponent createButtonPanel()
    {
        JPanel p = new JPanel();
        GridBagLayout gbl = new GridBagLayout();
        p.setLayout(gbl);
        GridBagConstraints gbc = new GridBagConstraints();

        gbc.gridx = 0;       gbc.gridy = 0;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 0.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(0, 0, 0, 0);
        JButton allButton = ButtonFactory.createButton(i18n("all"));
        allButton.setToolTipText(i18n("all_tt"));
        allButton.addActionListener(new ActionListener()
            {
                public void actionPerformed(ActionEvent e)
                {
                    setHourSelection(0, 23);
                    setDaySelection(0, 6);
                }
            });
        gbl.setConstraints(allButton, gbc);
        p.add(allButton);
            
        gbc.gridx = 0;       gbc.gridy = 1;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(COMPONENT_SPACE, 0, 0, 0);
        JButton noneButton = ButtonFactory.createButton(i18n("none"));
        noneButton.setToolTipText(i18n("none_tt"));
        noneButton.addActionListener(new ActionListener()
            {
                public void actionPerformed(ActionEvent e)
                {
                    setDaySelection(-1, -1);
                }
            });
        gbl.setConstraints(noneButton, gbc);
        p.add(noneButton);
        
        return p;
    }
    
    protected JComponent createLegendPanel()
    {
        JPanel p = new JPanel();
        GridBagLayout gbl = new GridBagLayout();
        p.setLayout(gbl);
        GridBagConstraints gbc = new GridBagConstraints();

        gbc.gridx = 0;       gbc.gridy = 0;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 0.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.CENTER;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(3, COMPONENT_SPACE, 0, 0);
        JPanel selIcon = new JPanel();
        selIcon.setOpaque(true);
        selIcon.setBackground(UIManager.getColor("textHighlight"));
        gbl.setConstraints(selIcon, gbc);
        p.add(selIcon);
            
        gbc.gridx = 1;       gbc.gridy = 0;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.CENTER;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        JComponent selLabel = new JLabel(i18n("selected"));
        gbl.setConstraints(selLabel, gbc);
        p.add(selLabel);
            
        gbc.gridx = 0;       gbc.gridy = 1;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 0.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.CENTER;
        gbc.fill = GridBagConstraints.NONE;
        JPanel unSelIcon = new JPanel();
        unSelIcon.setOpaque(true);
        unSelIcon.setBackground(UIManager.getColor("window"));
        gbl.setConstraints(unSelIcon, gbc);
        p.add(unSelIcon);
        
        gbc.gridx = 1;       gbc.gridy = 1;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.CENTER;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        JComponent unSelLabel = new JLabel(i18n("unselected"));
        gbl.setConstraints(unSelLabel, gbc);
        p.add(unSelLabel);
            
        return p;
    }
    
    protected JComponent createTimeDayPanel()
    {
        JTable t = new JTable(new TimeTableModel());
        timeTable = t;
        t.setRowSelectionAllowed(true);
        t.setColumnSelectionAllowed(true);
        t.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        t.setCellSelectionEnabled(true);
        t.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
	t.setPreferredSize(new Dimension(360, 400));
        t.setDefaultRenderer(Object.class, new TimeCellRenderer());
        t.setRowHeight(22);
	t.setShowGrid(false);

        t.setIntercellSpacing(new Dimension(0,0));
        TimeSelectionListener tsl = new TimeSelectionListener();
        ListSelectionModel lsm = t.getSelectionModel();
        lsm.addListSelectionListener(tsl);
        
        JTableHeader th = t.getTableHeader();
        th.setReorderingAllowed(false);
        th.setResizingAllowed(false);

        TimeHeaderRenderer thr = new TimeHeaderRenderer();
        
        TableColumnModel tcm = t.getColumnModel();
        tcm.addColumnModelListener(tsl);
        int columnCount = tcm.getColumnCount();
        TableColumn column = tcm.getColumn(0);
        column.setMinWidth(DAY_COLUMN_WIDTH);
        column.setResizable(false);
        column.setHeaderRenderer(thr);
        
        t.setPreferredScrollableViewportSize(new Dimension(t.getPreferredSize().width, t.getRowCount() * t.getRowHeight() + th.getSize().height));

        for(int i = 1; i < columnCount; i++)
        {
            TableColumn tc = tcm.getColumn(i);
            tc.setMinWidth(1);
            tc.setHeaderRenderer(thr);
        }
        
        JScrollPane sp = new JScrollPane(t);
        sp.setBorder(BorderFactory.createEmptyBorder());
        sp.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_NEVER);
        sp.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        return sp;
    }

    class TimeSelectionListener implements ListSelectionListener, TableColumnModelListener
    {
        public void columnAdded(TableColumnModelEvent e) {};
        public void columnRemoved(TableColumnModelEvent e) {};
        public void columnMoved(TableColumnModelEvent e) {};
        public void columnMarginChanged(ChangeEvent e) {};
        public void columnSelectionChanged(ListSelectionEvent e) 
        {
            updateDescription();
        };
        
        public void valueChanged(ListSelectionEvent e)
        {
            if(!e.getValueIsAdjusting())
            {
                int column = timeTable.getSelectedColumn();
                if(column == 0)
                {
                    int row = timeTable.getSelectedRow();
                    if(row != -1)
                    {
                        timeTable.setColumnSelectionInterval(1, 24);
                        timeTable.addRowSelectionInterval(row, row);
                    }
                }
            }
            updateDescription();
        }
        
        void updateDescription()
        {
            final String dayFormat = i18n("daySelect");
            final String timeFormat = i18n("timeSelect");
            int days[] = timeTable.getSelectedRows();
            StringBuffer sb = new StringBuffer();
            
            if(days.length > 0)
            {
                if(days.length == 1)
                {
                    sb.append(toDayString(days[0]));
                }
                else
                {
                    sb.append(MessageFormat.format(dayFormat, new Object[] 
                                { 
                                   toDayString(days[0]), 
                                   toDayString(days[days.length-1]) 
                                }));
                }
                    
                int hours[] = timeTable.getSelectedColumns();
                if(hours.length > 0)
                {
                    if(hours[0] > 0)
                    {
                        sb.append(", ");
                        if(hours.length == 1)
                        {
                            sb.append(toHourString(hours[0]-1, true));
                        }
                        else
                        {
                            sb.append(MessageFormat.format(timeFormat, new Object[] 
                                        { 
                                           toHourString(hours[0]-1, true), 
                                           toHourString(hours[hours.length-1], true) 
                                        }));
                        }
                    }
                }
            }
            selectionLabel.setText(sb.toString());
        }
    }
    
    /**
     * Returns localized string representing a time.
     * 
     * @param hour 0-23 time hour
     * @param showAMPM true if AM or PM is to be appended.
     * @return string representing specified hour, e.g. "4pm"
     */
    public String toHourString(int hour, boolean showAMPM)
    {
        String amPM = (hour < 12 ? "am" : "pm");
        if(hour > 12) hour -= 12;
        if(hour == 0) hour = 12;
        StringBuffer sb = new StringBuffer(String.valueOf(hour));
        if(showAMPM)
            sb.append(amPM);
        return sb.toString();
    }
    
    /**
     * Returns localized string representing a day.
     * For example toDayString(0) returns "Sunday" in US locale.
     * 
     * @param day    day of week
     * @return localized    string representing a day.
     */
    public String toDayString(int day)
    {
        return (String)dayOfWeek.elementAt(day);
    }

    /**
     * Selects all hours across all days: 24x7
     */
    public void selectAll()
    {
        setHourSelection(0, 23);
        setDaySelection(0, 6);
    }
    
    /**
     * Unselects all hours and days
     */
    public void selectNone()
    {
        setHourSelection(-1, -1);
        setDaySelection(-1, -1);
    }
    
    /**
     * Adds days to the existing selection.
     * Days are zero based.  For example:
     * 0 = First day of week (e.g. Sunday in US)
     * 6 = Last day of week (e.g. Saturday in US)
     * 
     * @param startDay starting day of selection, range: 0 to 6
     * @param endDay ending day of selection, range: 0 to 6
     */
    public void addDaySelection(int startDay, int endDay)
    {
        if(startDay == -1 || endDay == -1)
            timeTable.clearSelection();
        else
            timeTable.addRowSelectionInterval(startDay, endDay);
    }

    /**
     * Selects an interval of days, replacing existing selection.
     * Days are zero based.  For example:
     * 0 = First day of week (e.g. Sunday in US)
     * 6 = Last day of week (e.g. Saturday in US)
     * 
     * @param startDay starting day of selection, range: 0 to 6
     * @param endDay ending day of selection, range: 0 to 6
     */
    public void setDaySelection(int startDay, int endDay)
    {
        if(startDay == -1 || endDay == -1)
            timeTable.clearSelection();
        else
            timeTable.setRowSelectionInterval(startDay, endDay);
    }

    /**
     * Adds hours to the existing selection.
     * Hours are zero based.  For example:  
     * 0 means 12am, 12 means 12pm, 23 means 11pm
     * 
     * @param startHour starting hour of selection, range: 0 to 23
     * @param endHour ending hour of selection, range: 0 to 23
     */
    public void addHourSelection(int startHour, int endHour)
    {
        if(startHour == -1 || endHour == -1)
            timeTable.clearSelection();
        else
            timeTable.addColumnSelectionInterval(startHour+1, endHour+1);
    }
    
    /**
     * Selects an interval of hours, replacing existing selection.
     * Hours are zero based.  For example:
     * 0 means 12am, 12 means 12pm, 23 means 11pm
     * 
     * @param startHour starting hour of selection, range: 0 to 23
     * @param endHour ending hour of selection, range: 0 to 23
     */
    public void setHourSelection(int startHour, int endHour)
    {
        if(startHour == -1 || endHour == -1)
            timeTable.clearSelection();
        else
            timeTable.setColumnSelectionInterval(startHour+1, endHour+1);
    }
    
    public void setDayHourSelection(int day, int hour) {
        timeTable.changeSelection(day, hour+1, true, true);
    }
    
    /**
     * @return selected days.
     */
    public int[] getDaySelection()
    {
        return timeTable.getSelectedRows();
    }
    
    /**
     * @return selected hours.
     */
    public int[] getHourSelection()
    {
        int[] hours = timeTable.getSelectedColumns();
        for(int i = 0; i < hours.length; i++)
            hours[i]--;
        return hours;
    }
    
    class TimeTableModel extends DefaultTableModel
    {
        Object hourCell = new Object();
        
        public Class getColumnClass(int c) 
        {
            return getValueAt(0, c).getClass();
        }
                
        public boolean isCellEditable(int row, int col)
        {
            return false;
        }
        
        public int getRowCount()
        {
            return MAX_DAYS;
        }
        
        public int getColumnCount()
        {
            return 25;
        }
        
        public String getColumnName(int x)
        {
            return " ";
        }
                                 
        public Object getValueAt(int row, int column)
        {
            if(column == 0)
            {
                return toDayString(row);
            }
            return hourCell;
        }
    }
    
    class TimeHeaderRenderer extends JPanel implements TableCellRenderer
    {
        Border emptyBorder = BorderFactory.createEmptyBorder();
        Border ClickBorder = new ClickBorder();
        JLabel hourIconLabel = new JLabel();
        JLabel hourTextLabel = new JLabel();
        JPanel emptyPanel = new JPanel();
        ImageIcon sunIcon = new RemoteImage("com/netscape/management/client/components/images/sun.gif");
        ImageIcon moonIcon = new RemoteImage("com/netscape/management/client/components/images/moon.gif");
        
        public TimeHeaderRenderer()
        {
            // hourTextLabel.setFont(new Font("Verdana", Font.PLAIN, 9));
            hourTextLabel.setFont(new Font("SansSerif", Font.PLAIN, 9));
            hourTextLabel.setHorizontalAlignment(SwingConstants.CENTER);
            hourIconLabel.setHorizontalAlignment(SwingConstants.CENTER);
            GridBagLayout gbl = new GridBagLayout();
            setLayout(gbl);
            GridBagConstraints gbc = new GridBagConstraints();

            gbc.gridx = 0;       gbc.gridy = 0;
            gbc.gridwidth = 1;   gbc.gridheight = 1;
            gbc.weightx = 1.0;   gbc.weighty = 1.0;
            gbc.anchor = GridBagConstraints.SOUTH;
            gbc.fill = GridBagConstraints.HORIZONTAL;
            gbl.setConstraints(hourIconLabel, gbc);
            add(hourIconLabel);
                
            gbc.gridx = 0;       gbc.gridy = 1;
            gbc.gridwidth = 1;   gbc.gridheight = 1;
            gbc.weightx = 1.0;   gbc.weighty = 0.0;
            gbc.anchor = GridBagConstraints.SOUTH;
            gbc.fill = GridBagConstraints.HORIZONTAL;
            gbl.setConstraints(hourTextLabel, gbc);
            add(hourTextLabel);
                
            gbc.gridx = 0;       gbc.gridy = 2;
            gbc.gridwidth = 1;   gbc.gridheight = 1;
            gbc.weightx = 1.0;   gbc.weighty = 0.0;
            gbc.anchor = GridBagConstraints.SOUTH;
            gbc.fill = GridBagConstraints.HORIZONTAL;
            gbl.setConstraints(emptyPanel, gbc);
            add(emptyPanel);
        }

        public boolean isFocusTraversable()
        { 
            return false; 
        }
        
        public Component getTableCellRendererComponent(JTable table, Object value,
                            boolean isSelected, boolean hasFocus, 
                            int row, int column)
        {
            emptyPanel.setBorder(column == 0 ? emptyBorder : ClickBorder);
            if(column % 2 == 1)
            {
                hourTextLabel.setText(toHourString(column-1, false));
                if(column == 1 || column == 23)
                    hourIconLabel.setIcon(moonIcon);
                if(column == 13)
                    hourIconLabel.setIcon(sunIcon);
            }
            else
            {
                hourTextLabel.setText("");
                hourIconLabel.setIcon(null);
            }
            return this;
        }
    }

    class TimeCellRenderer extends JButton implements TableCellRenderer
    {
        Border flatBorder = new FlatBorder();
        Border emptyBorder = BorderFactory.createEmptyBorder();
        Border ClickBorder = new ClickBorder();
        Border dotBorder = new DotBorder(UIManager.getColor("controlShadow"), false, false, true, true);
        
        public boolean isFocusTraversable()
        { 
            return false; 
        }
        
        public Component getTableCellRendererComponent(JTable table, Object value,
                            boolean isSelected, boolean hasFocus, 
                            int row, int column)
        {
            if(value instanceof String)
            {
                Color backgroundColor = UIManager.getColor("Button.background");
                Border border = ClickBorder;
                if(isSelected)
                {
                    //border = flatBorder;
                    backgroundColor = UIManager.getColor("controlShadow");
                }
                setBorder(border);
                setBackground(backgroundColor);
                setText((String)value);
            }
            else
            {
                Color backgroundColor = UIManager.getColor("window");
                if(isSelected)
                {
                    backgroundColor = UIManager.getColor("textHighlight");
                }
                setBackground(backgroundColor);
                setBorder(dotBorder);
                setText("");
            }
                
            return this;
        }
    }
}
