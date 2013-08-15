package com.netscape.cmscore.logging;

import java.util.Properties;

import com.netscape.certsrv.logging.ILogEvent;
import com.netscape.certsrv.logging.ILogEventFactory;
import com.netscape.certsrv.logging.ILogQueue;
import com.netscape.certsrv.logging.ILogger;

/**
 * Default logging stub for testing.
 */
public class LoggerDefaultStub implements ILogger {
    public void log(int evtClass, int source, String msg) {
    }

    public void log(int evtClass, Properties props, int source, String msg) {
    }

    public void log(int evtClass, int source, int level, String msg) {
    }

    public void log(int evtClass, Properties props, int source, int level, String msg) {
    }

    public void log(int evtClass, int source, int level, String msg, Object param) {
    }

    public void log(int evtClass, int source, int level, String msg, Object params[]) {
    }

    public void log(int evtClass, Properties props, int source, String msg, Object param) {
    }

    public void log(int evtClass, Properties props, int source, int level, String msg, Object param) {
    }

    public void log(int evtClass, Properties prop, int source, int level, String msg, Object params[]) {
    }

    public void log(int evtClass, int source, String msg, boolean multiline) {
    }

    public void log(int evtClass, Properties props, int source, String msg, boolean multiline) {
    }

    public void log(int evtClass, int source, int level, String msg, boolean multiline) {
    }

    public void log(int evtClass, Properties props, int source, int level, String msg, boolean multiline) {
    }

    public void log(int evtClass, int source, int level, String msg, Object param, boolean multiline) {
    }

    public void log(int evtClass, Properties props, int source, String msg, Object param, boolean multiline) {
    }

    public void log(int evtClass, Properties props, int source, int level, String msg, Object param, boolean multiline) {
    }

    public void log(int evtClass, Properties prop, int source, int level, String msg, Object params[], boolean multiline) {
    }

    public ILogEvent create(int evtClass, Properties prop, int source, int level, String msg, Object params[],
            boolean multiline) {
        return null;
    }

    public void register(int evtClass, ILogEventFactory f) {
    }

    public ILogQueue getLogQueue() {
        return null;
    }
}
