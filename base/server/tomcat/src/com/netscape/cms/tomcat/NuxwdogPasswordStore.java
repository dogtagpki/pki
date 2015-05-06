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

import com.redhat.nuxwdog.WatchdogClient;


public class NuxwdogPasswordStore implements org.apache.tomcat.util.net.jss.IPasswordStore {

    // Note: pwCache is a temporary construct needed because nuxwdog currently
    // does not expose a putPassword() method.  When this is added, pwCache will
    // no longer be needed.
    private Hashtable<String, String> pwCache = null;
    private ArrayList<String> tags = null;

    private final String PROMPT_PREFIX = "Please provide the password for ";
    private String instanceId;

    @Override
    public void init(String confFile) throws IOException {
        if (!startedByNuxwdog()) {
            throw new IOException("process not started by nuxwdog");
        }

        tags = new ArrayList<String>();

        if (confFile != null) {
            populateTokenTags(confFile);
        }

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

    private void populateTokenTags(String confFile) throws IOException {
        Properties props = new Properties();
        InputStream in = new FileInputStream(confFile);
        props.load(in);

        tags.add("internal");

        String tokenList = props.getProperty("cms.tokenList");
        if (StringUtils.isNotEmpty(tokenList)) {
            for (String token: StringUtils.split(tokenList,',')) {
                tags.add("hardware-" + token);
            }
        }

        instanceId = props.getProperty("instanceId");
    }

    private void addTag(String tag) {
        if (!tags.contains(tag)) {
            tags.add(tag);
        }
    }

    public String getPassword(String tag, int iteration) {
        if (pwCache.containsKey(tag)) {
            return pwCache.get(tag);
        }

        String prompt = PROMPT_PREFIX + tag + ":";
        if (StringUtils.isNotEmpty(instanceId)) {
            prompt = "[" + instanceId + "] " + prompt;
        }

        String pwd = WatchdogClient.getPassword(prompt, iteration);

        if (pwd != null) {
            addTag(tag);
        }
        return pwd;
    }

    @Override
    public String getPassword(String tag){
        return getPassword(tag, 0);
    }

    @Override
    public Enumeration<String> getTags() {
        return  Collections.enumeration(tags);
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
