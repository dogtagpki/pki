package com.netscape.cmstools.profile;

import java.util.Collection;

import com.netscape.certsrv.profile.ProfileDataInfo;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class ProfileFindCLI extends CLI {

    public ProfileCLI parent;

    public ProfileFindCLI(ProfileCLI parent) {
        super("find", "Find profiles");
        this.parent = parent;
    }

    public void printHelp() {
        formatter.printHelp(parent.name + "-" + name + " [FILTER] [OPTIONS...]", options);
    }

    public void execute(String[] args) throws Exception {

        Collection<ProfileDataInfo> infos = parent.client.listProfiles().getProfileInfos();
        boolean first = true;

        for (ProfileDataInfo info: infos) {
            if (first) {
                first = false;
            } else {
                System.out.println();
            }
            ProfileCLI.printProfileDataInfo(info);
        }

        MainCLI.printMessage("Number of entries returned " + infos.size());
    }

}
