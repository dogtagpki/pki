package com.netscape.cms.tomcat;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Hashtable;

import org.apache.commons.lang.StringUtils;

import com.netscape.cmsutil.util.Keyring;

public class NuxwdogPasswordStore implements org.apache.tomcat.util.net.jss.IPasswordStore {

    // Note: pwCache is a temporary construct needed because nuxwdog currently
    // does not expose a putPassword() method.  When this is added, pwCache will
    // no longer be needed.
    private Hashtable<String, String> pwCache = null;
    private ArrayList<String> tags = null;

    @Override
    public void init(String confFile) throws IOException {
        if (!startedByNuxwdog()) {
            throw new IOException("process not started by nuxwdog");
        }

        tags = new ArrayList<String>();

        pwCache = new Hashtable<String, String>();
    }

    private boolean startedByNuxwdog() {
        // confirm that process was started by nuxwdog
        String wdPipeName = System.getenv("WD_PIPE_NAME");
        if (StringUtils.isNotEmpty(wdPipeName)) {
            return true;
        }
        return false;

    }

    private void addTag(String tag) {
        if (!tags.contains(tag)) {
            tags.add(tag);
        }
    }

    @Override
    public String getPassword(String tag, int iteration) {
        if (pwCache.containsKey(tag)) {
            return pwCache.get(tag);
        }
        String pwd = null;

        try {
            pwd = Keyring.getPassword(tag, "");
        } catch (Exception e) {
            e.printStackTrace();
        }

        if (pwd != null) {
            addTag(tag);
        }
        return pwd;
    }

    @Override
    public String getPassword(String tag) {
        return getPassword(tag, 0);
    }

    @Override
    public Enumeration<String> getTags() {
        return Collections.enumeration(tags);
    }

    @Override
    public Object putPassword(String tag, String password) {
        addTag(tag);
        return pwCache.put(tag, password);
    }

    @Override
    public void commit() throws IOException, ClassCastException, NullPointerException {
        // Nothing required here
    }

}
