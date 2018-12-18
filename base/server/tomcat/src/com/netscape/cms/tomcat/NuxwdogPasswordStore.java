package com.netscape.cms.tomcat;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Properties;

import org.apache.commons.lang.StringUtils;

import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.util.Keyring;

public class NuxwdogPasswordStore implements org.apache.tomcat.util.net.jss.IPasswordStore {

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
            loadTags(confFile);
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

    /**
     * Load the required tags by reading CS.cfg. PKI server does not have any idea about the required
     * tags when Nuxwdog is enabled. This method must be part of init in order for the PKI server to
     * load the corresponding values during server start
     *
     * @param confFile Path to CS.cfg
     * @throws IOException
     */
    private void loadTags(String confFile) throws IOException {
        Properties props = new Properties();
        InputStream in = new FileInputStream(confFile);
        props.load(in);

        tags.add(CryptoUtil.INTERNAL_TOKEN_NAME);

        String tokenList = props.getProperty("cms.tokenList");
        if (StringUtils.isNotEmpty(tokenList)) {
            for (String token: StringUtils.split(tokenList,',')) {
                tags.add("hardware-" + token);
            }
        }

        id = props.getProperty("instanceId");
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
