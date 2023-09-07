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
package com.netscape.cmscore.request;

public class RecoverThread extends Thread {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(RecoverThread.class);

    RequestQueue queue;

    public RecoverThread(RequestQueue queue) {
        super("RequestRecoverThread");
        this.queue = queue;
    }

    @Override
    public void run() {
        try {
            queue.recoverWillBlock();
        } catch (Exception e) {
            logger.error("RecoverThread: " + e.getMessage(), e);
        }
    }
}
