//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.job;

import java.util.Collection;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.netscape.certsrv.base.DataCollection;
import com.netscape.certsrv.util.JSONSerializer;


/**
 * @author Endi S. Dewata
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class JobCollection extends DataCollection<JobInfo> implements JSONSerializer {

    @Override
    public Collection<JobInfo> getEntries() {
        return super.getEntries();
    }

}
