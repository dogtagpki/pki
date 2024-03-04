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

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.util.Calendar;
import java.util.GregorianCalendar;

import javax.swing.JComboBox;
import javax.swing.JPanel;
import javax.swing.JTextField;

import com.netscape.management.nmclf.SuiConstants;

class DatePicker extends JPanel implements SuiConstants {
    Calendar calendar;
    JComboBox monthField = new JComboBox();
    JTextField yearField = new JTextField(8);
    SpinControl yearSpinner;
    DayPicker dayPicker;

    static private final ResourceSet _resource = new ResourceSet("com.netscape.management.client.util.default");

    static private final String JANUARY = _resource.getString("DatePicker","January");
    static private final String FEBRUARY = _resource.getString("DatePicker","February");
    static private final String MARCH = _resource.getString("DatePicker","March");
    static private final String APRIL = _resource.getString("DatePicker","April");
    static private final String MAY = _resource.getString("DatePicker","May");
    static private final String JUNE = _resource.getString("DatePicker","June");
    static private final String JULY = _resource.getString("DatePicker","July");
    static private final String AUGUST = _resource.getString("DatePicker","August");
    static private final String SEPTEMBER = _resource.getString("DatePicker","September");
    static private final String OCTOBER = _resource.getString("DatePicker","October");
    static private final String NOVEMBER = _resource.getString("DatePicker","November");
    static private final String DECEMBER = _resource.getString("DatePicker","December");

    public int getYear() {
        return calendar.get(Calendar.YEAR);
    }

    public int getMonth() {
        return calendar.get(Calendar.MONTH);
    }

    public int getDay() {
        return dayPicker.getDay();
    }

    public DatePicker(Calendar calendar) {
        this.calendar = calendar;
        String months[] = {
            JANUARY,
            FEBRUARY,
            MARCH,
            APRIL,
            MAY,
            JUNE,
            JULY,
            AUGUST,
            SEPTEMBER,
            OCTOBER,
            NOVEMBER,
            DECEMBER
        };

        monthField.getAccessibleContext().setAccessibleDescription(_resource.getString("DatePicker","month"));
        yearField.getAccessibleContext().setAccessibleDescription(_resource.getString("DatePicker","year"));

        GridBagLayout gridbag = new GridBagLayout();
        GridBagConstraints c = new GridBagConstraints();
        setLayout(gridbag);

        GridBagUtil.constrain(this, monthField, 0, 0, 1, 1, 0.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                              0, 0, COMPONENT_SPACE, COMPONENT_SPACE);

        GridBagUtil.constrain(this, yearField, 1, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                0, 0, COMPONENT_SPACE, 0);

        yearSpinner = new SpinControl(yearField);
        yearSpinner.setToolTipText(_resource.getString("DatePicker","year_tt"));
        GridBagUtil.constrain(this, yearSpinner, 2, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                0, 0, COMPONENT_SPACE, 0);

        dayPicker = new DayPicker(calendar);
        GridBagUtil.constrain(this, dayPicker, 0, 1, 3, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                0, 0, COMPONENT_SPACE, 0);

        for (int i = 0; i < months.length; i++) {
            monthField.addItem(months[i]);
        }
        monthField.setSelectedIndex(calendar.get(Calendar.MONTH));
        yearField.setText(String.valueOf(calendar.get(Calendar.YEAR)));
        monthField.addActionListener(new MonthChangeListener());
        yearField.addFocusListener(new YearFocusListener());
        yearSpinner.addSpinListener(new YearSpinListener());
    }

    class MonthChangeListener implements ActionListener {
        public void actionPerformed(ActionEvent event) {
            calendar.set(Calendar.MONTH, monthField.getSelectedIndex());
            dayPicker.updatePicker();
        }
    }

    int getIntFromString(String text) {
        Integer integer = Integer.valueOf(text);
        return integer.intValue();
    }

    class YearSpinListener implements ISpinListener {
        public void actionUp(SpinEvent e) {
            calendar.add(Calendar.YEAR, 1);
            update();
        }

        public void actionDown(SpinEvent e) {
            calendar.add(Calendar.YEAR, -1);
            update();
        }
    }

    class YearFocusListener implements FocusListener {
        public void focusGained(FocusEvent event) {
        }

        public void focusLost(FocusEvent event) {
            int newYear = getIntFromString(yearField.getText());
            if ((newYear < 1900) || (newYear > 9999))// TODO: review Y2K compliance
            {
                Calendar c = new GregorianCalendar();
                newYear = c.get(Calendar.YEAR);
            }
            calendar.set(Calendar.YEAR, newYear);
            update();
        }
    }

    int oldYear = 0;
    public void update() {
        int year = getYear();
        if (oldYear != year) {
            yearField.setText(String.valueOf(year));
            dayPicker.updatePicker();
            oldYear = year;
        }
    }
}
