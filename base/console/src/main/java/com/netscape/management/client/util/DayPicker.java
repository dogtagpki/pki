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
package com.netscape.management.client.util;

import java.awt.Color;
import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.Calendar;

import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.UIManager;
import javax.swing.border.Border;

import com.netscape.management.nmclf.SuiConstants;

/**
 * A panel the displays and allows selection of a day
 * in a month.
 *
 * @see DateTimePicker
 */
class DayPicker extends JPanel implements SuiConstants {
    Calendar calendar;
    DayLabel dayLabelArray[][];
    FocusListener dayFocusListener = new DayFocusListener();
    MouseListener dayMouseListener = new DayMouseListener();
    Border emptyBorder = BorderFactory.createEmptyBorder(1, 6, 1, 6);
    DayLabel selectedDayLabel;
    DayKeyListener dayKeyListener = new DayKeyListener();

    static private final ResourceSet _resource = new ResourceSet("com.netscape.management.client.util.default");

    static private final String MONDAY = _resource.getString("DayPicker", "Monday");
    static private final String TUESDAY = _resource.getString("DayPicker", "Tuesday");
    static private final String WEDNESDAY = _resource.getString("DayPicker", "Wednesday");
    static private final String THURSDAY = _resource.getString("DayPicker", "Thursday");
    static private final String FRIDAY = _resource.getString("DayPicker", "Friday");
    static private final String SATURDAY = _resource.getString("DayPicker", "Saturday");
    static private final String SUNDAY = _resource.getString("DayPicker", "Sunday");

    /**
     * constructor
     *
     * @param calendar provide the current calendar object to indicated the date
     */
    public DayPicker(Calendar calendar) {
        this.calendar = calendar;
        String days[] = { SUNDAY, MONDAY, TUESDAY, WEDNESDAY, THURSDAY, FRIDAY, SATURDAY }; // TODO: localize via Calendar.getFirstDayOfWeek(), ie France=MTWTFSS

        GridBagLayout gridbag = new GridBagLayout();
        GridBagConstraints c = new GridBagConstraints();
        setLayout(gridbag);
        setBackground(Color.white);
        setOpaque(true);
        setBorder(UITools.createLoweredBorder());
        for (int i = 0; i < days.length; i++) {
            JComponent dayHeader = new JLabel(days[i]);
            dayHeader.setBackground(Color.darkGray);
            dayHeader.setForeground(Color.white);
            dayHeader.setBorder(emptyBorder);
            dayHeader.setOpaque(true);
            GridBagUtil.constrain(this, dayHeader, i, 0, 1, 1, 0.0,
                    0.0, GridBagConstraints.NORTHWEST,
                    GridBagConstraints.HORIZONTAL, 0, 0,
                    COMPONENT_SPACE, 0);
        }

        int maxWeeks = calendar.getMaximum(Calendar.WEEK_OF_MONTH);
        int maxDays = calendar.getMaximum(Calendar.DAY_OF_WEEK);
        dayLabelArray = new DayLabel[maxWeeks][maxDays];

        for (int y = 0; y < maxWeeks; y++) {
            for (int x = 0; x < maxDays; x++) {
                DayLabel dayLabel = new DayLabel();
                dayLabel.addKeyListener(dayKeyListener);
                dayLabelArray[y][x] = dayLabel;
                GridBagUtil.constrain(this, dayLabel, x, y + 1, 1, 1,
                        0.0, 0.0, GridBagConstraints.NORTHWEST,
                        GridBagConstraints.NONE, 0, 0, COMPONENT_SPACE, 0);
            }
        }
        updatePicker();
    }

    /**
      * get the current focused component
      *
      * @return the component which has focused
      */
    public JComponent getFocusComponent() {
        return selectedDayLabel;
    }

    /**
      * get the current day
      *
      * @return the current day
      */
    public int getDay() {
        return calendar.get(Calendar.DAY_OF_MONTH);
    }

    int getIntFromString(String text) {
        Integer integer = Integer.valueOf(text);
        return integer.intValue();
    }

    class DayLabel extends JLabel {
        public DayLabel() {
            addFocusListener(dayFocusListener);
            addMouseListener(dayMouseListener);
            setForeground(UIManager.getColor("controlText"));
            setBackground(UIManager.getColor("window"));
            setBorder(emptyBorder);
            setOpaque(true);
        }

        public boolean isFocusTraversable() {
            return true;
        }

        public void setSelected(boolean isSelected) {
            if (!isSelected) {
                setForeground(UIManager.getColor("controlText"));
                setBackground(UIManager.getColor("window"));
            } else {
                if (selectedDayLabel == this) {
                    setForeground(UIManager.getColor("textHighlightText"));
                    setBackground(UIManager.getColor("textHighlight"));
                } else {
                    setForeground(UIManager.getColor("textText"));
                    setBackground(UIManager.getColor("control"));
                }
            }
            setText(getText());
        }
    }

    /**
      * update the day picker with the current internal calendar object
      */
    public void updatePicker() {
        if (selectedDayLabel != null)
            selectedDayLabel.setSelected(false);

        boolean pastEndOfMonth = false;
        int maxWeeks = calendar.getMaximum(Calendar.WEEK_OF_MONTH);
        int maxDays = calendar.getMaximum(Calendar.DAY_OF_WEEK);
        int toDay = calendar.get(Calendar.DAY_OF_MONTH);
        calendar.set(Calendar.DAY_OF_MONTH, 1);
        int currentDay;

        for (int y = 0; y < maxWeeks; y++) {
            int max = calendar.getMaximum(Calendar.DAY_OF_MONTH);
            for (int x = 0; x < maxDays; x++) {
                if (calendar.get(Calendar.DAY_OF_WEEK) == x + 1 &&
                        !pastEndOfMonth) {
                    currentDay = calendar.get(Calendar.DAY_OF_MONTH);
                    DayLabel dayLabel = dayLabelArray[y][x];
                    if (currentDay == toDay) {
                        dayLabel.setSelected(true);
                        selectedDayLabel = dayLabel;
                    }

                    dayLabel.setText(String.valueOf(currentDay));
                    calendar.roll(Calendar.DAY_OF_MONTH, true);
                    int nextDay = calendar.get(Calendar.DAY_OF_MONTH);
                    if (nextDay < currentDay)
                        pastEndOfMonth = true;
                } else
                    dayLabelArray[y][x].setText(" ");
            }
        }
        calendar.set(Calendar.DAY_OF_MONTH, toDay);
        refreshUI();
    }

    void refreshUI() {
        // this is necessary to recalc new width, otherwise we get ellipsis
        invalidate();
        Component parent = getParent();
        if (parent != null) {
            parent.validate();
        }
    }
    class DayFocusListener implements FocusListener {
        DottedBorder dottedBorder = new DottedBorder();

        public void focusGained(FocusEvent event) {
            DayLabel label = (DayLabel) event.getComponent();
            label.setBackground(UIManager.getColor("textHighlight"));
            label.setForeground(UIManager.getColor("textHighlightText"));
            String text = label.getText();
            if (text.equals(" ")) {
                selectedDayLabel.requestFocus();
            } else {
                selectedDayLabel.setSelected(false);
                selectedDayLabel = label;
                selectedDayLabel.setSelected(true);
                calendar.set(Calendar.DAY_OF_MONTH,
                        getIntFromString(label.getText()));
                //Border emptyBorder = BorderFactory.createEmptyBorder(0,1,1,1);
                //label.setBorder(BorderFactory.createCompoundBorder(dottedBorder, emptyBorder));
            }
        }

        public void focusLost(FocusEvent event) {
            DayLabel label = (DayLabel) event.getComponent();

            if (label == selectedDayLabel) {
                label.setBackground(UIManager.getColor("control"));
                label.setForeground(UIManager.getColor("textText"));
            } else {
                label.setForeground(UIManager.getColor("controlText"));
                label.setBackground(UIManager.getColor("window"));
            }
            label.setText(label.getText());
        }
    }

    class DayKeyListener extends KeyAdapter {
        public void keyPressed(KeyEvent e) {
            int keycode = e.getKeyCode();
            if (keycode == KeyEvent.VK_UP) {
                int minDaysInMonth =
                        calendar.getMinimum(Calendar.DAY_OF_MONTH);
                int maxDaysInMonth =
                        calendar.getMaximum(Calendar.DAY_OF_MONTH);
                int maxDaysInWeek =
                        calendar.getMaximum(Calendar.DAY_OF_WEEK);
                int today = calendar.get(Calendar.DAY_OF_MONTH);
                if (today - maxDaysInWeek >= minDaysInMonth) {
                    calendar.add(Calendar.DAY_OF_MONTH, -maxDaysInWeek);
                    updatePicker();
                    selectedDayLabel.requestFocus();
                    refreshUI();
                }
            } else if (keycode == KeyEvent.VK_DOWN) {
                int minDaysInMonth =
                        calendar.getMinimum(Calendar.DAY_OF_MONTH);
                int maxDaysInMonth =
                        calendar.getMaximum(Calendar.DAY_OF_MONTH);
                int maxDaysInWeek =
                        calendar.getMaximum(Calendar.DAY_OF_WEEK);
                int today = calendar.get(Calendar.DAY_OF_MONTH);
                if (today + maxDaysInWeek <= maxDaysInMonth) {
                    calendar.add(Calendar.DAY_OF_MONTH, maxDaysInWeek);
                    updatePicker();
                    selectedDayLabel.requestFocus();
                    refreshUI();
                }
            } else if (keycode == KeyEvent.VK_LEFT) {
                calendar.roll(Calendar.DAY_OF_MONTH, false);
                updatePicker();
                selectedDayLabel.requestFocus();
                refreshUI();
            } else if (keycode == KeyEvent.VK_RIGHT) {
                calendar.roll(Calendar.DAY_OF_MONTH, true);
                updatePicker();
                selectedDayLabel.requestFocus();
                refreshUI();
            }
        }
    }

    class DayMouseListener extends MouseAdapter {
        public void mousePressed(MouseEvent event) {
            JLabel label = (JLabel) event.getComponent();
            label.requestFocus();
        }
    }
}
