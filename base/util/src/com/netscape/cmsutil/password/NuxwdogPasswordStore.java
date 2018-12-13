package com.netscape.cmsutil.password;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Properties;

import org.apache.commons.lang.StringUtils;

import com.netscape.cmsutil.util.Keyring;

public class NuxwdogPasswordStore implements IPasswordStore {

    // Note: pwCache is a temporary construct needed because nuxwdog currently
    // does not expose a putPassword() method.  When this is added, pwCache will
    // no longer be needed.
    private Hashtable<String, String> pwCache = null;
    private ArrayList<String> tags = null;
    private String id;

    @Override
    public void init(String confFile) throws IOException {
        if (!startedByNuxwdog()) {
            throw new IOException("process not started by nuxwdog");
        }

        tags = new ArrayList<String>();

        pwCache = new Hashtable<String, String>();

        if(confFile != null) {
            loadInstanceID(confFile);
        }
    }

    private boolean startedByNuxwdog() {
        // confirm that process was started by nuxwdog
        String wdPipeName = System.getenv("WD_PIPE_NAME");
        if (StringUtils.isNotEmpty(wdPipeName)) {
            return true;
        }
        return false;

    }

    private void loadInstanceID(String confFile) throws IOException {
        Properties props = new Properties();
        InputStream in = new FileInputStream(confFile);
        props.load(in);

        id = props.getProperty("instanceId");
    }

    private void addTag(String tag) {
        if (!tags.contains(tag)) {
            tags.add(tag);
        }
    }

    @Override
    public String getPassword(String tag, int iteration) {
        // Check the Hash table for availability
        if (pwCache.containsKey(tag)) {
            return pwCache.get(tag);
        }
        String pwd = null;

        try {
            String keyringTag = id + "/" + tag;
            pwd = Keyring.getPassword(keyringTag, "");
        } catch (Exception e) {
            e.printStackTrace();
        }

        if (pwd != null) {
            addTag(tag);
        }
        return pwd;
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

    public void setId(String id) {
        this.id = id;
    }

    public String getId() {
        return id;
    }

}
