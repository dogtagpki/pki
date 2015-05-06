package com.netscape.cms.tomcat;
import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleEvent;
import org.apache.catalina.LifecycleListener;
import org.apache.commons.lang.StringUtils;

import com.redhat.nuxwdog.WatchdogClient;

public class PKIListener implements LifecycleListener {

    private boolean startedByWD = false;

    @Override
    public void lifecycleEvent(LifecycleEvent event) {
        String method = "NuxwdogReader:lifecycleEvent";
        if (event.getType().equals(Lifecycle.BEFORE_INIT_EVENT)) {
            System.out.println(method + ": before init event");
            String wdPipeName = System.getenv("WD_PIPE_NAME");
            if (StringUtils.isNotEmpty(wdPipeName)) {
                startedByWD = true;
                System.out.println(method + ": Initializing the watchdog");
                WatchdogClient.init();
            }
        } else if (event.getType().equals(Lifecycle.AFTER_START_EVENT)) {
            System.out.println(method + "After start event");
            if (startedByWD) {
                System.out.println(method + ": Sending endInit to the Watchdog");
                WatchdogClient.sendEndInit(0);
            }
        }
    }

}
