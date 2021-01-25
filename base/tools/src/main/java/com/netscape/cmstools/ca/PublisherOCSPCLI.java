//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.ca;

import org.dogtagpki.cli.CLI;

public class PublisherOCSPCLI extends CLI {

    public PublisherCLI publisherCLI;

    public PublisherOCSPCLI(PublisherCLI publisherCLI) {
        super("ocsp", "OCSP publisher management commands", publisherCLI);
        this.publisherCLI = publisherCLI;

        addModule(new PublisherOCSPAddCLI(this));
    }
}
