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
package com.netscape.management.client;

import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JProgressBar;
import javax.swing.ToolTipManager;

/**
 * A status item that displays a progress gauge, on a
 * 0 to 100 percent scale.   It can also show a busy state
 * (STATE_BUSY) that indicates ongoing progress until
 * it the state is set back to 0.
 */
public class StatusItemProgress extends JProgressBar implements IStatusItem {
    private static final int MODE_PERCENT = 0;
    private static final int MODE_BUSY = 2;
    private static final int PONG_WIDTH = 15;
    private static final int INCREMENT = 3;
    private static final int DELAY = 30;

    int _percent = 0;
    int _mode = MODE_PERCENT;

    public static Integer STATE_BUSY = Integer.valueOf(-1);
    protected String _id = null;
    private javax.swing.Timer busyTimer = null;

    static private final String I18N_IDLE = Framework.i18n("progress", "idle");
    static private final String I18N_BUSY = Framework.i18n("progress", "busy");

    public StatusItemProgress(String id) {
        setID(id);
        setMinimum(0);
        setMaximum(100);
        setMaximumSize(new Dimension(200, 11));
        busyTimer = new javax.swing.Timer(DELAY, new BusyTimerActionListener());
        ToolTipManager.sharedInstance().registerComponent(this);
    }

    public StatusItemProgress(String id, int percent) {
        this(id);
        setValue(percent);
    }

    /**
     * Returns the associated view Component.
     */
    public Component getComponent() {
        return this;
    }

    /**
     * Returns unique, language independant ID.
     */
    public String getID() {
        return _id;
    }

    /**
     * Sets ID
     */
    public void setID(String id) {
        _id = id;
    }

    /**
     * Sets state.
     */
    public void setState(Object state) {
        if (state.equals(STATE_BUSY)) {
            _mode = MODE_BUSY;
            busyTimer.start();
        } else {
            _mode = MODE_PERCENT;
            busyTimer.stop();
        }
        setValue(((Integer) state).intValue());
    }

    /**
      * @deprecated  use setState(StatusItemProgress.STATE_BUSY) instead
      */
    // Miodrag: this method is used by cert4.x servers. need it for compatibility
    @Deprecated
    public void start() {
        setState(STATE_BUSY);
    }

    /**
      * @deprecated  use setState(new Integer(0)) instead
      */
    // Miodrag: this method is used by cert4.x servers. need it for compatibility
    @Deprecated
    public void stop() {
        setState(Integer.valueOf(0));
    }

    /**
     * Returns current state.
     */
    public Object getState() {
        return Integer.valueOf(getValue());
    }

    /**
     * Overridden to provide task status statistics in tooltip for accessibility compliance
     */
    public String getToolTipText() {
       if (getValue() == getMinimum()) {
            return I18N_IDLE;
        } else {
            return I18N_BUSY;
        }
    }

    class BusyTimerActionListener implements ActionListener
    {
        public void actionPerformed(ActionEvent e)
        {
            int value = getValue();
            value += INCREMENT;
            if(value > 100)
                value = 0;
            setValue(value);
        }
    }
}
