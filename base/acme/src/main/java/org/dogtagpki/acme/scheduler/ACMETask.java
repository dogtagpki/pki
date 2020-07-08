//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.scheduler;

/**
 * @author Endi S. Dewata
 */
public abstract class ACMETask {

    protected ACMETaskConfig config;

    public ACMETaskConfig getConfig() {
        return config;
    }

    public void setConfig(ACMETaskConfig config) {
        this.config = config;
    }

    public void init() throws Exception {
    }

    public void run() throws Exception {
    }
}
