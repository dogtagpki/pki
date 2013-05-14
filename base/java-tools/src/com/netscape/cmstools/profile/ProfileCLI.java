package com.netscape.cmstools.profile;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.util.Arrays;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.apache.commons.lang.StringUtils;

import com.netscape.certsrv.profile.ProfileClient;
import com.netscape.certsrv.profile.ProfileData;
import com.netscape.certsrv.profile.ProfileDataInfo;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class ProfileCLI extends CLI {
    public MainCLI parent;
    public ProfileClient client;

    public ProfileCLI(MainCLI parent) {
        super("profile", "Profile management commands");
        this.parent = parent;

        addModule(new ProfileFindCLI(this));
        addModule(new ProfileShowCLI(this));
        addModule(new ProfileAddCLI(this));
        addModule(new ProfileModifyCLI(this));
        addModule(new ProfileRemoveCLI(this));
        addModule(new ProfileEnableCLI(this));
        addModule(new ProfileDisableCLI(this));
    }

    public void printHelp() {

        System.out.println("Commands:");

        int leftPadding = 1;
        int rightPadding = 25;

        for (CLI module : modules.values()) {
            String label = name + "-" + module.getName();

            int padding = rightPadding - leftPadding - label.length();
            if (padding < 1)
                padding = 1;

            System.out.print(StringUtils.repeat(" ", leftPadding));
            System.out.print(label);
            System.out.print(StringUtils.repeat(" ", padding));
            System.out.println(module.getDescription());
        }
    }

    public void execute(String[] args) throws Exception {

        client = new ProfileClient(parent.client);

        if (args.length == 0) {
            printHelp();
            System.exit(1);
        }

        String command = args[0];
        String[] commandArgs = Arrays.copyOfRange(args, 1, args.length);

        if (command == null) {
            printHelp();
            System.exit(1);
        }

        CLI module = getModule(command);
        if (module != null) {
            module.execute(commandArgs);

        } else {
            System.err.println("Error: Invalid command \"" + command + "\"");
            printHelp();
            System.exit(1);
        }
    }

    public static void printProfileDataInfo(ProfileDataInfo info) {
        System.out.println("Profile ID:  " + info.getProfileId());
        System.out.println("Profile URL: " + info.getProfileURL());
    }

    public static void printProfile(ProfileData profileData) {
        // TODO Auto-generated method stub

    }

    public static void saveProfileToFile(String filename, ProfileData data)
            throws JAXBException, FileNotFoundException {
        JAXBContext context = JAXBContext.newInstance(ProfileData.class);
        Marshaller marshaller = context.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

        FileOutputStream stream = new FileOutputStream(filename);
        marshaller.marshal(data, stream);

        MainCLI.printMessage("Saved profile " + data.getId() + " to " + filename);
    }

    public static ProfileData readProfileFromFile(String filename)
            throws JAXBException, FileNotFoundException {
        ProfileData data = null;
        JAXBContext context = JAXBContext.newInstance(ProfileData.class);
        Unmarshaller unmarshaller = context.createUnmarshaller();
        FileInputStream fis = new FileInputStream(filename);
        data = (ProfileData) unmarshaller.unmarshal(fis);
        return data;
    }
}
