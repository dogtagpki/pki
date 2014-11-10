import argparse
import PkiLib.pkiprofilelib as pkiprofilelib
from lxml import etree
import sys
 
def main():

    parser = argparse.ArgumentParser(description="Create and Edit Profiles")
    required = parser.add_argument_group('Mandatory Arguments') 
    userChoices = ('user', 'smime', 'dualcert', 'server', 'ca','other')
    parser.add_argument('--editprofile', help="Edit existing profile xml")
    parser.add_argument('--new', choices = userChoices, help="Create new profile xml")
    parser.add_argument('--profileId', help="Id of the Profile to be created")
    parser.add_argument('--profilename', help="Name of the profile to be created")
    parser.add_argument('--profiledescription', help="Description of the profile to be created")
    parser.add_argument('--inputfile', help="Provide xml file to be modified")
    parser.add_argument('--outputfile', help="Save the profile in output file",required=True)
    parser.add_argument('--subjectNamePattern', help="Subject Name pattern constraint to be passed")
    parser.add_argument('--subjectNameDefault', type=str, help="Default Subject Name to be appended")
    parser.add_argument('--notBefore', type=str, help="Days not before the expiry date")
    parser.add_argument('--notAfter', type=str, help="Days not After the expiry date")
    parser.add_argument('--validfor', type=str, help="Total validity period of cert")
    parser.add_argument('--maxvalidity', type=str, help="Total Maximum validity should not exceed Total validity")
    parser.add_argument('--keyusageextensions', type=str, help="Add Key usage Extensions to be enabled in profile")
    parser.add_argument('--netscapeextensions', type=str, help="Specify the Netscape Extensions to be added")
    parser.add_argument('--crlextension', type=str, help="Specify CRL url")
    parser.add_argument('--isCA', type=str, help="Specify True/False value")
    parser.add_argument('--PathLength', type=str, help="Specify Maximum path length")
    parser.add_argument('--altType', type=str, help="Provide subject Alt type")
    parser.add_argument('--altPattern', type=str, help="Provide Subject Alt Pattern")
    parser.add_argument('--ExtOID', type=str, help="Provide ExtOID supplied in csr")
    args = parser.parse_args()
    if args.new:
	new_profile(args)
    elif args.editprofile:
        New_Edit_Profile(args)

def new_profile(args):

    if (args.new == 'user') or (args.new == 'smime'):
        profile_user_input_parser(args)
    elif (args.new == 'server') or (args.new == 'ca') or (args.new == 'other'):
        profile_server_input_parser(args)
    elif args.new == 'dualcert':
        profile_dualcert_input_parser(args)  
    else:
	print "In appropriate option.Exiting"
	sys.exit(1)
    return 0

def Generate_Profile_hash(args):

    Profile_Input_Dict = {}
    ProfileId = args.profileId
    Profile_Input_Dict['ProfileId'] = ProfileId
    if (args.new == 'user') or (args.new == 'smime'):
        ProfileName = 'Manual User Dual-Use Certificate Enrollment'
        ProfileDescription = 'This certificate profile is for enrolling user certificates'
        Profile_Input_Dict['Key_Generation_Class'] = 'keyGenInputImpl'
        Profile_Input_Dict['Key_Generate_InputId'] = '1'
        Profile_Input_Dict['subject_Name_Input_Id'] = '2'
        Profile_Input_Dict['Submitter_Info_InputId'] = '3'
        keylist = ('keyUsageCritical','keyUsageDigitalSignature','keyUsageNonRepudiation','keyUsageKeyEncipherment')
        subjectPattern = 'UID=.*'
        policysetname = 'pkitest1'
    elif (args.new == 'server') or (args.new == 'other'):
        ProfileName = "Manual Server Certificate Enrollment"
        ProfileDescription = "This certificate profile is for enrolling dual user certificates"
        Profile_Input_Dict['Key_Generation_Class'] = 'certReqInputImpl'
        Profile_Input_Dict['Key_Generate_InputId'] = '1'
        Profile_Input_Dict['Submitter_Info_InputId'] = '2'
        keylist = ('keyUsageCritical','keyUsageDigitalSignature','keyUsageNonRepudiation','keyUsageKeyEncipherment')
        subjectPattern = 'CN=.*'
        policysetname = 'pkitest1'
    elif args.new == 'dualcert':
        ProfileName = "Manual User Signing and Encryption Certificates Enrollment"
        ProfileDescription = "This certificate profile is for enrolling dual user certificates"
        Profile_Input_Dict['Key_Generation_Class'] = 'dualKeyGenInputImpl'
        Profile_Input_Dict['Key_Generate_InputId'] = '1'
        Profile_Input_Dict['subject_Name_Input_Id'] = '2'
        Profile_Input_Dict['Submitter_Info_InputId'] = '3'
        keylist = ('keyUsageCritical','keyUsageKeyEncipherment')
        subjectPattern = 'UID=.*'
        policysetname = 'encryptionCertSet'
    elif args.new == 'ca':
        policysetname = 'caCertSet'
        ProfileName = "Manual Certificate Manager Signing Certificate Enrollment"
        ProfileDescription = "This certificate profile is for enrolling Certificate Authority certificates."
        Profile_Input_Dict['Key_Generation_Class'] = 'certReqInputImpl'
        Profile_Input_Dict['Key_Generate_InputId'] = '1'
        Profile_Input_Dict['Submitter_Info_InputId'] = '2'
        keylist = ('keyUsageCritical', 'keyUsageDigitalSignature', 'keyUsageNonRepudiation', 'keyUsageKeyCertSign', 'keyUsageCrlSign')
        subjectPattern = 'CN=.*'
        if args.PathLength:
            PathLength = args.PathLength
        else:
            PathLength = "-1"
        Profile_Input_Dict['PathLength'] = PathLength
        if args.isCA:
            isCA = args.isCA
        else:
            isCA = "true"
        Profile_Input_Dict['isCA'] = isCA
   
    Profile_Input_Dict['PolicySet'] = policysetname

    if args.subjectNamePattern:
        Profile_Input_Dict['Subject_Pattern'] = args.subjectNamePattern
    else:
        Profile_Input_Dict['Subject_Pattern'] = subjectPattern
    if args.subjectNameDefault:
        Profile_Input_Dict['subjectNameDefault'] = args.subjectNameDefault
    else:
        Profile_Input_Dict['subjectNameDefault'] = None

    if args.profilename:
        Profile_Input_Dict['name'] = args.profilename
    else:
        Profile_Input_Dict['name'] = ProfileName

    if args.profiledescription:
        Profile_Input_Dict['Description'] = args.profiledescription
    else:
        Profile_Input_Dict['Description'] =  ProfileDescription
    if args.keyusageextensions:
        Profile_Input_Dict['Key_List'] = args.keyusageextensions
    else:
        Profile_Input_Dict['Key_List'] = keylist
    
    if args.notBefore:
        Profile_Input_Dict['NotBefore'] = args.notBefore
    else:
        Profile_Input_Dict['NotBefore'] = '30'

    if args.notAfter:
        Profile_Input_Dict['NotAfter'] = args.notAfter
    else:
        Profile_Input_Dict['NotAfter'] = '30'

    if args.validfor:
        validfor = args.validfor
        Profile_Input_Dict['Validity'] = args.validfor
    else:
        Profile_Input_Dict['Validity'] = '180'

    if args.maxvalidity:
        Profile_Input_Dict['MaxValidity'] = args.maxvalidity
    else:
        Profile_Input_Dict['MaxValidity'] = '365'

    if args.netscapeextensions:
        Profile_Input_Dict['NetscapeExtensions'] = args.netscapeextensions

    if args.new == 'smime':
        Profile_Input_Dict['Generic_extensions'] = 'true'

    if args.crlextension:
        Profile_Input_Dict['crlurl'] = args.crlextension

    if args.altPattern:
        altPattern = args.altPattern
    else:
        altPattern = "$request.requestor_email$"
    Profile_Input_Dict['altPattern'] = altPattern

    if args.altType:
        altType = args.altType
    else:
        altType = 'RFC822Name'
    Profile_Input_Dict['altType'] = altType

    if args.ExtOID:
        Profile_Input_Dict['ExtOID'] = args.ExtOID

    return Profile_Input_Dict

def profile_user_input_parser(args):

    Profile_Input_Dict = Generate_Profile_hash(args)
    root_element, PolicySets = Create_Profile(Profile_Input_Dict)
    root_element, PolicySet = pkiprofilelib.Create_Policy(root_element, PolicySets, Profile_Input_Dict['PolicySet'])
    et = Add_Policies(root_element,PolicySet,Profile_Input_Dict) 
    et.write(args.outputfile, pretty_print=True)

def profile_server_input_parser(args):

    Profile_Input_Dict = Generate_Profile_hash(args)
    root_element, PolicySets = Create_Profile(Profile_Input_Dict)
    root_element, PolicySet = pkiprofilelib.Create_Policy(root_element, PolicySets, Profile_Input_Dict['PolicySet'])
    et = Add_Policies(root_element,PolicySet,Profile_Input_Dict) 
    et.write(args.outputfile, pretty_print=True)
        
def profile_dualcert_input_parser(args):

    Profile_Input_Dict1 = Generate_Profile_hash(args)
    root_element, PolicySets = Create_Profile(Profile_Input_Dict1)
    root_element, policyset = pkiprofilelib.Create_Policy(root_element, PolicySets, Profile_Input_Dict1['PolicySet'])
    et = Add_Policies(root_element,policyset,Profile_Input_Dict1)
    et.write(args.outputfile, pretty_print=True)

    keylist2 = ('keyUsageCritical','keyUsageDigitalSignature','keyUsageDigitalSignature', 'keyUsageNonRepudiation')
    subjectPattern =  Profile_Input_Dict1['Subject_Pattern']
    subjectDefault = Profile_Input_Dict1['subjectNameDefault']
    notBefore = Profile_Input_Dict1['NotBefore']
    notAfter = Profile_Input_Dict1['NotAfter']
    validfor = Profile_Input_Dict1['Validity']
    maxvalidity = Profile_Input_Dict1['MaxValidity']
    altType = Profile_Input_Dict1['altType'] 
    altPattern = Profile_Input_Dict1['altPattern']

    Profile_Input_Dict2 = {
            'PolicySet': 'signingCertSet',
            'Subject_Pattern': subjectPattern,
            'subjectNameDefault': subjectDefault,
            'Key_List': keylist2,
            'NotBefore': notBefore,
            'NotAfter': notAfter,
            'Validity': validfor,
            'MaxValidity': maxvalidity,
            'altType': altType,
            'altPattern': altPattern
            }
    root_element, policyset = pkiprofilelib.Create_Policy(root_element, PolicySets, Profile_Input_Dict2['PolicySet'])
    et = Add_Policies(root_element,policyset,Profile_Input_Dict2)
    et.write(args.outputfile, pretty_print=True)
    
def Create_Profile(Profile_Input_Dict):

    root_element = pkiprofilelib.new_profile(Profile_Input_Dict['ProfileId'], Profile_Input_Dict['name'], 
                                    Profile_Input_Dict['Description'])
    pkiprofilelib.key_gen(root_element, Profile_Input_Dict['Key_Generation_Class'], 
                                    Profile_Input_Dict['Key_Generate_InputId'])

    if Profile_Input_Dict.has_key('subject_Name_Input_Id'):
        pkiprofilelib.subject_name_input(root_element, Profile_Input_Dict['subject_Name_Input_Id'])
        pkiprofilelib.submitter_info(root_element, Profile_Input_Dict['Submitter_Info_InputId'])
    else:
       pkiprofilelib.submitter_info(root_element,Profile_Input_Dict['Submitter_Info_InputId'])
      
    pkiprofilelib.output_info(root_element)
    # Create Policy Set
    root_element, PolicySets = pkiprofilelib.Create_PolicySets(root_element)
    return root_element, PolicySets

def New_Edit_Profile(args):

    # Get Root Element and PolicySet
    parser = etree.XMLParser(remove_blank_text=True)
    root_element = etree.parse(args.editprofile,parser)
    PolicySet = root_element.find('./PolicySets/PolicySet')

    if args.profilename:
        Profilename = root_element.find('name')
        Profilename.text = args.profilename

    if args.profiledescription:
        ProfileDescription = root_element.find('description')
        ProfileDescription.text = args.profiledescription
    
    if args.subjectNamePattern and args.subjectNameDefault is None:
        pkiprofilelib.Subject_Name_Default(root_element, PolicySet,args.subjectNamePattern,None)

    if args.subjectNamePattern is None and args.subjectNameDefault:
        pkiprofilelib.Subject_Name_Default(root_element, PolicySet,None,args.subjectNameDefault)

    if args.subjectNamePattern and args.subjectNameDefault:
        pkiprofilelib.Subject_Name_Default(root_element, PolicySet,args.subjectNamePattern,args.subjectNameDefault)
    
    if args.keyusageextensions:
        pkiprofilelib.Key_Usage_Default(root_element,PolicySet, args.keyusageextensions)

    if args.maxvalidity and args.validfor:
        pkiprofilelib.Validity_Default(root_element,PolicySet, args.validfor, args.maxvalidity)    
    
    if args.notBefore and args.notAfter:
        pkiprofilelib.No_Default(root_element, PolicySet, args.notBefore , args.notAfter)

    if args.netscapeextensions:
        pkiprofilelib.Netscape_Certificate_Type_Extension_Default(root_element,PolicySet,args.netscapeextensions)

    if args.crlextension:
        pkiprofilelib.crl_Distribution_Points_Ext_Default(root_element,PolicySet,args.crlextension)
     
    if args.PathLength and args.isCA:
        pkiprofilelib.Basic_Constraints_Extension_Default(root_element,PolicySet,args.PathLength,args.isCA)

    if args.altType and args.altPattern:
        pkiprofilelib.Subject_Alt_Name_Constraint(root_element,PolicySet,args.altType, args.altPattern)

    if args.ExtOID:
         pkiprofilelib.User_Supplied_Extension_Default(root_element,PolicySet,args.ExtOID)
    
    root_element.write(args.outputfile, pretty_print=True)


def Add_Policies(root_element, PolicySet, Profile_Input_Dict):

    if  Profile_Input_Dict['subjectNameDefault'] is None:
        pkiprofilelib.Subject_Name_Default(root_element,PolicySet, Profile_Input_Dict['Subject_Pattern'],None)
    else:
        pkiprofilelib.Subject_Name_Default(root_element,PolicySet, Profile_Input_Dict['Subject_Pattern'],Profile_Input_Dict['subjectNameDefault'])


    if not (Profile_Input_Dict.has_key('PathLength') and Profile_Input_Dict.has_key('isCA')):
        pkiprofilelib.No_Default(root_element, PolicySet, Profile_Input_Dict['NotBefore'],Profile_Input_Dict['NotAfter'])
        pkiprofilelib.Validity_Default(root_element,PolicySet, Profile_Input_Dict['Validity'],Profile_Input_Dict['MaxValidity'])
        pkiprofilelib.Extended_Key_Usage_Extension_Default(root_element,PolicySet)
        pkiprofilelib.Subject_Alt_Name_Constraint(root_element,PolicySet,Profile_Input_Dict['altType'],Profile_Input_Dict['altPattern'])

        if Profile_Input_Dict.has_key('ExtOID'):
            pkiprofilelib.User_Supplied_Extension_Default(root_element,PolicySet,Profile_Input_Dict['ExtOID'])

    pkiprofilelib.Key_Default(root_element, PolicySet)
    pkiprofilelib.Authority_Key_Identifier_Default(root_element,PolicySet)
    pkiprofilelib.AIA_Extension_Default(root_element,PolicySet)
    pkiprofilelib.Key_Usage_Default(root_element, PolicySet,Profile_Input_Dict['Key_List'])
    pkiprofilelib.Signing_Alg(root_element,PolicySet)


    if Profile_Input_Dict.has_key('Generic_extensions'):
        pkiprofilelib.Generic_Extension(root_element,PolicySet)

    if Profile_Input_Dict.has_key('NetscapeExtensions'):
        pkiprofilelib.Netscape_Certificate_Type_Extension_Default(root_element,PolicySet, Profile_Input_Dict['NetscapeExtensions'])

    if Profile_Input_Dict.has_key('crlurl'):
        pkiprofilelib.crl_Distribution_Points_Ext_Default(root_element,PolicySet,Profile_Input_Dict['crlurl'])

    if Profile_Input_Dict.has_key('PathLength') and Profile_Input_Dict.has_key('isCA'):
        pkiprofilelib.Basic_Constraints_Extension_Default(root_element,PolicySet,Profile_Input_Dict['PathLength'], Profile_Input_Dict['isCA'])
        pkiprofilelib.CA_Certificate_Validity_Default(root_element,PolicySet)
        pkiprofilelib.Subject_Key_Identifier_Extension_Default(root_element,PolicySet)

    et = etree.ElementTree(root_element)

    return et

if __name__=='__main__':
    main()

