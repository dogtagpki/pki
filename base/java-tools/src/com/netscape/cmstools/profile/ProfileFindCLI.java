package com.netscape.cmstools.profile;

import java.util.Collection;

import com.netscape.certsrv.profile.ProfileDataInfo;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class ProfileFindCLI extends CLI {

    public ProfileCLI profileCLI;

    public ProfileFindCLI(ProfileCLI profileCLI) {
        super("find", "Find profiles", profileCLI);
        this.profileCLI = profileCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [FILTER] [OPTIONS...]", options);
    }

    public void execute(String[] args) throws Exception {

        Collection<ProfileDataInfo> infos = profileCLI.profileClient.listProfiles().getProfileInfos();
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
