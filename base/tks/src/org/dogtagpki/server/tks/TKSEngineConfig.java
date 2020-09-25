//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks;

import java.util.Arrays;
import java.util.Collection;

import org.apache.commons.lang3.StringUtils;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStorage;

public class TKSEngineConfig extends EngineConfig {

    public TKSEngineConfig(ConfigStorage storage) {
        super(storage);
    }

    public TKSConfig getTKSConfig() {
        return getSubStore("tks", TKSConfig.class);
    }

    public Collection<String> getTPSConnectorIDs() throws EBaseException {
        String list = getString("tps.list", "");
        return Arrays.asList(list.split(","));
    }

    public void setTPSConnectorIDs(Collection<String> list) throws EBaseException {
        putString("tps.list", StringUtils.join(list, ","));
    }
}
