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
package com.netscape.admin.certsrv;

import java.lang.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import com.netscape.management.client.*;
import com.netscape.management.client.util.*;

/**
 * Status bar item for continuous progress feedback
 * [This one is borrowed from directory server]
 *
 * @author  kirwin
 * @version %I%, %G%
 * @date    4/8/98
 * @see     com.netscape.admin.certsrv
 */
public class StatusItemContinuousProgress extends StatusItemProgress
{
    private int _val = 0;
    private static int VALUE_INCREMENT = 9;
    private static int UPDATE_INTERVAL = 50;
    private static int INITIAL_DELAY = 0;
    private ProgressTracker _thread;
    private boolean _running = false;

	public StatusItemContinuousProgress(String id) {
        super(id, 0);
        _thread = new ProgressTracker();
        _thread.start();
	}

    public void start() {
        if (!_running) {
            _running = true;
            _val = 0;
            setValue(0);
            _thread.resume();
        }
    }

    public void stop() {
        if (_running) {
            _running = false;
            _val = 0;
            setValue(0);
        }
    }

    private void increment() {
        Graphics g = getGraphics();
        if ((_val += VALUE_INCREMENT) > 99) {
            _val = 0;
            if (g != null) {
                Rectangle r = getBounds();
                g.clearRect(0, 0, r.width, r.height);
            }
        }
        setValue(_val);
        update(g);
    }

    private class ProgressTracker extends Thread {

        public void run() {
            while (true) {
                while (_running) {
                    increment();
                    try {
                        sleep(UPDATE_INTERVAL);
                    } catch (InterruptedException e) {
                        Debug.println("sleep exception");
                    }
                }
                suspend();
            }
        }
    }
}
