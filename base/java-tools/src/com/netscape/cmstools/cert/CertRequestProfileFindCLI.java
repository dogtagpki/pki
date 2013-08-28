package com.netscape.cmstools.cert;

import java.util.Collection;

import com.netscape.certsrv.profile.ProfileDataInfo;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.profile.ProfileCLI;

public class CertRequestProfileFindCLI extends CLI {

    public CertCLI certCLI;

    public CertRequestProfileFindCLI(CertCLI certCLI) {
        super("request-profile-find", "List Enrollment templates", certCLI);
        this.certCLI = certCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <Profile ID>", options);
    }

    public void execute(String[] args) throws Exception {
        Collection<ProfileDataInfo> infos = certCLI.certClient.listEnrollmentTemplates().getProfileInfos();
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

