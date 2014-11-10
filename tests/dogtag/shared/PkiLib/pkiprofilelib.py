#!/usr/bin/python
# -*- coding: utf-8 -*
from lxml import etree
import sys
import re
import PkiLib.pkiconstraintslib as constraints
import PkiLib.pkicommonlib as common

def new_profile(ProfileId,ProfileName,ProfileDescription):

    #our profile starts with Profile Tag
    root = etree.Element("Profile", id=ProfileId)
    #print type(root)
    
    # In future the this could be a arguement to be passed
    classId = etree.SubElement(root, "classId").text = 'caEnrollImpl'
    
    # Profile Name
    name = etree.SubElement(root, "name").text = ProfileName

    # Profile Description
    description = etree.SubElement(root, "description").text = ProfileDescription

    enabled = etree.SubElement(root, "enabled").text = 'false'
    visible = etree.SubElement(root, "visible").text = 'true'
    enabledBy = etree.SubElement(root, "enabledBy")
    authzAcl = etree.SubElement(root, "authzAcl")
    renew = etree.SubElement(root, "renewal").text = 'false'
    xmlOutput = etree.SubElement(root, "xmlOutput").text = 'false'

    return root

def key_gen(root,InputClassID,InputId):

    ''' This function for storing the Key Generation 
        Possible values of InputClassID:
            certReqInputImpl : For Server Cert 
            keyGenInputImpl : For User Cert/SMIMECert
            dualKeyGenInputImpl: For Dual Cert

        @parameters InputClassID
    '''
    Input = etree.SubElement(root, "Input", id = 'i'+InputId)
    classId = etree.SubElement(Input, 'ClassID').text = InputClassID
    name = etree.SubElement(Input, 'Name').text = 'Key Generation'

    if InputClassID == 'dualKeyGenInputImpl':
       input_attributes = [
               ('cert_request_type','dual_keygen_request_type','Key Generation Request Typ'),
               ('cert_request','dual_keygen_request', 'Key Generation Request')]

    elif InputClassID == 'keyGenInputImpl':
       input_attributes = [
               ('cert_request_type','keygen_request_type', 'Key Generation Request Type'),
               ('cert_request','keygen_request', 'Key Generation Request')]

    elif InputClassID == 'certReqInputImpl':
       input_attributes = [
               ('cert_request_type','cert_request_type', 'Certificate Request Type'),
               ('cert_request','cert_request', 'Certificate Request')]
    else:
        print '%s did not match with valid Input ClassId', InputClassID
        sys.exit(1)
    
    for idx, (name, syntax, description) in enumerate(input_attributes):

        Attribute = etree.SubElement(Input, 'Attribute', name=name)
        Descriptor = etree.SubElement(Attribute, 'Descriptor')
        syntax = etree.SubElement(Descriptor, 'Syntax').text = syntax
        Description = etree.SubElement(Descriptor, 'Description').text = description

def subject_name_input(root, InputId):
    
    subject_name_values = [
            ('sn_uid', 'UID'),
            ('sn_e','Email'),
            ('sn_cn','Common Name'),
            ('sn_ou3','Organizational Unit 3'),
            ('sn_ou2','Organizational Unit 2'),
            ('sn_ou1','Organizational Unit 1'),
            ('sn_ou','Organizational Unit'),
            ('sn_o','Organization'),
            ('sn_c','Country')]
    
    Input = etree.SubElement(root, "Input", id = 'i'+InputId)
    classId = etree.SubElement(Input, 'ClassID').text = 'subjectNameInputImpl'
    name = etree.SubElement(Input, 'Name').text = 'Subject Name'

    for idx, (attr_name, desc_value) in enumerate(subject_name_values):
    
         Attribute = etree.SubElement(Input, 'Attribute', name=attr_name)
         Descriptor = etree.SubElement(Attribute, 'Descriptor')
         syntax = etree.SubElement(Descriptor, 'Syntax').text = 'string'
         description = etree.SubElement(Descriptor, 'Description').text = desc_value


def submitter_info(root, InputId):

    Input = etree.SubElement(root, "Input", id='i'+InputId)
    classId = etree.SubElement(Input, 'ClassID').text = 'submitterInfoInputImpl'
    name = etree.SubElement(Input, 'Name').text = 'Requestor Information'

    requestor_info_values = [
            ('requestor_name', 'Requestor Name'),
            ('requestor_email', 'Requestor Email'),
            ('requestor_phone', 'Requestor Phone')
            ]
    for idx, (attr_name, desc_value) in enumerate(requestor_info_values):

        Attribute = etree.SubElement(Input, 'Attribute', name=attr_name)
        Descriptor = etree.SubElement(Attribute, 'Descriptor')
        syntax = etree.SubElement(Descriptor, 'Syntax').text = 'string'
        description = etree.SubElement(Descriptor, 'Description').text = desc_value

def output_info(root):

    output = etree.SubElement(root, "Output", id="o1")
    Name = etree.SubElement(output, 'name').text = 'Certificate Output'
    output_classId = etree.SubElement(output, 'classId').text = 'certOutputImpl'

    output_attributes = [
            ('pretty_cert', 'pretty_print', 'Certificate Pretty Print'),
            ('b64_cert', 'pretty_print', 'Certificate Base-64 Encoded')]

    for idx, (name, syntax, description) in enumerate(output_attributes):
        Attribute = etree.SubElement(output, 'attributes', name=name)
        Descriptor = etree.SubElement(Attribute, 'Descriptor')
        Syntax = etree.SubElement(Descriptor, 'Syntax').text = syntax
        Description = etree.SubElement(Descriptor, 'Description').text = description

def Create_PolicySets(root):

    PolicySets = etree.SubElement(root, "PolicySets")
    return root, PolicySets
    

def Create_Policy(root_element, PolicySets, policysetname):
    
    #PolicySets = root_element.find('./PolicySets')
    policyset = etree.SubElement(PolicySets, 'PolicySet')
    policySetId = etree.SubElement(policyset, 'id').text = policysetname
    return root_element, policyset
   


def get_policyId(PolicySet):

    PolicyValue = '1'
    if len(PolicySet) > 1:
        PolicyValue = '1'
        for valuedef in PolicySet.iterchildren(tag='value'):
            value = valuedef.get('id')

        PolicyValue = int(value) + 1
        return str(PolicyValue)
    else:
        return PolicyValue

def get_current_policyvalue(root):
    Policy_Value = root.findall('./PolicySets/PolicySet/value')
    mydict = {}
    for key in Policy_Value:
	PolicyValues=key.items()[0][1]
        classId=key[0].get('classId')   
        mydict[PolicyValues]=classId
    return mydict

def Subject_Name_Default(root_element,PolicySet,subjectPattern,subjectDefault):

    # Check if the policy is already defined
    javaclass = 'userSubjectNameDefaultImpl'

    result = common.check_policy(PolicySet, javaclass)

    if result is False:

        #Get Policy ID
        pvalue = get_policyId(PolicySet)
        Subject_Name_Default_description = 'This default populates a User-Supplied Certificate Subject Name to the request'

        # Policy Value
        Policy_Value = etree.SubElement(PolicySet, 'value', id=pvalue)

        if subjectDefault:
            Policy_definition = etree.SubElement(Policy_Value, 'def', classId='subjectNameDefaultImpl',id='Subject Name Default')
        else:
            Policy_definition = etree.SubElement(Policy_Value, 'def', classId='userSubjectNameDefaultImpl',id='Subject Name Default')
        Policy_description = etree.SubElement(Policy_definition, 'description').text = Subject_Name_Default_description

        # Policy Attributes
        Subject_Name_Default_attributes = [('name','string','NULL','Subject Name','NULL')]
        common.policy_attributes(Policy_definition, Subject_Name_Default_attributes)

        # Policy Parameters
        if subjectDefault:
            Subject_Name_Default_params = [('name',subjectDefault)]
            common.policy_parameters(Policy_definition,Subject_Name_Default_params)
    
        # Policy Constraints
        constraints.subjectNameConstraintImpl(Policy_Value,subjectPattern)
        
    else:
        Policy_Value = common.get_Element_PolicyValue(PolicySet, javaclass)
        if subjectDefault:
            Policy_Definition = Policy_Value[0]
            Policy_Definition.set('classId', 'subjectNameDefaultImpl')
            policy_param_name = etree.SubElement(Policy_Definition, 'params', name='name')
            policy_param_value = etree.SubElement(policy_param_name, 'value').text=subjectDefault
        if subjectPattern:
            CurrentValue = Policy_Value.find('./constraint/constraint/value')
            CurrentValue.text = subjectPattern
        

def Key_Usage_Default(root, PolicySet, keylist):
    ''' This function defines Key Usage Default Policy '''

    javaclass = 'keyUsageExtDefaultImpl'

    result = common.check_policy(PolicySet, javaclass)

    if result is False:
        #Get Policy ID
        pvalue = get_policyId(PolicySet)
    
        s1 = 'This default populates a Key Usage Extension (2.5.29.15) to the request,The default values are Criticality=true'
        s2 = 'Digital Signature=true, Non-Repudiation=true,Key Encipherment=true, Data Encipherment=false, Key Agreement=false'
        s3 = 'Key Certificate Sign=false, Key CRL Sign=false, Encipher Only=false, Decipher Only=false'
        Key_Usage_Default_description = s1 + s2 + s3
    
        # Policy Value
        Policy_Value = etree.SubElement(PolicySet, 'value', id=pvalue)
    
        # Policy Definition
        Policy_definition = etree.SubElement(Policy_Value, 'def', 
              id='Key Usage Default',classId='keyUsageExtDefaultImpl')
        Policy_description = etree.SubElement(Policy_definition, 'description').text = Key_Usage_Default_description

        # Policy Attributes #name,syntax,constraint,description,defaultvalue
        Key_Usage_Default_attributes = [
                ('keyUsageCritical','boolean','NULL','Criticality','false'),
                ('keyUsageDigitalSignature','boolean','NULL','Digital Signature','false'),
                ('keyUsageNonRepudiation','boolean','NULL','Non-Repudiation','false'),
                ('keyUsageKeyEncipherment','boolean','NULL','Key Encipherment','false'),
                ('keyUsageDataEncipherment','boolean','NULL','Data Encipherment','false'),
                ('keyUsageKeyAgreement','boolean','NULL','Key Agreement','false'),
                ('keyUsageKeyCertSign','boolean','NULL','Key CertSign','false'),
                ('keyUsageCrlSign','boolean','NULL','CRL Sign','false'),
                ('keyUsageEncipherOnly','boolean','NULL','Encipher Only','false'),
                ('keyUsageDecipherOnly','boolean','NULL','Decipher Only','false'),
                ]
        common.policy_attributes(Policy_definition, Key_Usage_Default_attributes)

        # Policy Parameters
        Key_Usage_Default_parms = [
                ('keyUsageCritical', common.check_ext_key_usage(keylist,'keyUsageCritical')),
                ('keyUsageDigitalSignature', common.check_ext_key_usage(keylist,'keyUsageDigitalSignature')),
                ('keyUsageNonRepudiation', common.check_ext_key_usage(keylist,'keyUsageNonRepudiation')),
                ('keyUsageKeyEncipherment', common.check_ext_key_usage(keylist,'keyUsageKeyEncipherment')),
                ('keyUsageDataEncipherment', common.check_ext_key_usage(keylist,'keyUsageDataEncipherment')),
                ('keyUsageKeyAgreement', common.check_ext_key_usage(keylist,'keyUsageKeyAgreement')),
                ('keyUsageKeyCertSign', common.check_ext_key_usage(keylist,'keyUsageKeyCertSign')),
                ('keyUsageCrlSign', common.check_ext_key_usage(keylist,'keyUsageCrlSign')),
                ('keyUsageEncipherOnly', common.check_ext_key_usage(keylist,'keyUsageEncipherOnly')),
                ('keyUsageDecipherOnly', common.check_ext_key_usage(keylist,'keyUsageDecipherOnly'))
                ]
        common.policy_parameters(Policy_definition,Key_Usage_Default_parms)
        
        # Policy Constraint
        constraints.keyUsageExtConstraintImpl(Policy_Value,keylist)

    else:

        Policy_Value = common.get_Element_PolicyValue(PolicySet, javaclass)
        # Change Policy Parameters
        mylist = re.split(',', keylist)
        for v in mylist:
            result_param = Policy_Value.find("./def/params[@name=\"%s\"]/value" % v)
            result_param.text = 'true'
        # Change Policy Constraints
        for v in mylist:
            result_constraint = Policy_Value.find("./constraint/constraint[@id=\"%s\"]/value" % v)
            result_constraint.text = 'true'
   
def CA_Certificate_Validity_Default(root,PolicySet):

    javaclass = 'caValidityDefaultImpl'
    result = common.check_policy(PolicySet, javaclass)

    if result is False:
        #Get Policy ID
        pvalue = get_policyId(PolicySet)
        CA_Certificate_Validity_Default_description = 'This default populates a Certificate Validity to the request. The default values are Range=7305 in days'
    
        # Policy Value
        Policy_Value = etree.SubElement(PolicySet, 'value', id=pvalue)

        # Policy Definition
        Policy_definition = etree.SubElement(Policy_Value, 'def', 
                id='CA Certificate Validity Default', classId='caValidityDefaultImpl')
        Policy_description = etree.SubElement(Policy_definition, 'description').text = CA_Certificate_Validity_Default_description
   
        # Policy Attributes
        CA_Certificate_Validity_Default_attributes = [
                ('notBefore','string','NULL','Not Before','NULL'),
                ('notAfter','string','NULL','notAfter','NULL'),
                ('bypassCAnotafter','boolean','NULL','Bypass CA notAfter constraint','false')]

        common.policy_attributes(Policy_definition, CA_Certificate_Validity_Default_attributes)

        # Policy Parameters
        CA_Certificate_Validity_Default_params = [
            ('range', '7305'),
            ('startTime', '0'),
            ('bypassCAnotafter', '')
            ]
        common.policy_parameters(Policy_definition,CA_Certificate_Validity_Default_params)

        # Policy Constraints
        constraints.validityConstraintImpl(Policy_Value, 365, 7305)

    else:

        Policy_Value = common.get_Element_PolicyValue(PolicySet, javaclass)

def Key_Default(root,PolicySet):

    ''' This function Defines key default policy'''
    javaclass = 'userKeyDefaultImpl'
    result = common.check_policy(PolicySet, javaclass)
    if result is False:

        #Get Policy ID
        pvalue = get_policyId(PolicySet)

        # Description
        Key_Default_description = 'This default populates a User-Supplied Certificate Key to the request'

        # Policy Value
        Policy_Value = etree.SubElement(PolicySet, 'value', id=pvalue)

        ### Policy Defintion
        Policy_definition = etree.SubElement(Policy_Value, 'def', id='Key Default', classId='userKeyDefaultImpl')
        Policy_description = etree.SubElement(Policy_definition, 'description').text = Key_Default_description
      
        ### Policy Attributes
        Key_Default_attributes = [
                ('TYPE','string','readonly','Key Type','NULL'),
                ('LEN','string','readonly','Key Length','NULL'),
                ('KEY','string','readonly','Key','NULL')]
    
        common.policy_attributes(Policy_definition, Key_Default_attributes)
        constraints.keyConstraintImpl(Policy_Value)
    else:
        Policy_Value = common.get_Element_PolicyValue(PolicySet, javaclass)

def Authority_Key_Identifier_Default(root,PolicySet):

    ''' This function Defines Authority Key Identifier Default Policy'''
    javaclass = 'authorityKeyIdentifierExtDefaultImpl'
    result = common.check_policy(PolicySet, javaclass)
    if result is False:

        #Get Policy ID 
        pvalue = get_policyId(PolicySet)

        # Description
        Authority_Key_Identifier_Default_description = 'This default populates an Authority Key Identifier Extension (2.5.29.35) to the request.'

        # Policy Value
        Policy_Value = etree.SubElement(PolicySet, 'value', id=pvalue)

        # Policy Definition
        Policy_definition = etree.SubElement(Policy_Value, 'def', 
                id='Authority Key Identifier Default', 
             classId='authorityKeyIdentifierExtDefaultImpl')
        Policy_description = etree.SubElement(Policy_definition, 'description').text = Authority_Key_Identifier_Default_description
    
        # Policy Attributes
        Authority_Key_Identifier_Default_attributes = [
                ('critical', 'string','readonly','Criticality','NULL'),
                ('keyid', 'string', 'readonly', 'Key ID', 'NULL')
                ]

        common.policy_attributes(Policy_definition, Authority_Key_Identifier_Default_attributes)

        # Constraint Definition
        constraints.noConstraintImpl(Policy_Value)

    else:
        Policy_Value = common.get_Element_PolicyValue(PolicySet, javaclass)

def Basic_Constraints_Extension_Default(root,PolicySet,PathLength, isCA):
    
    ''' This function Defines Basic Constraints Extension Default Policy'''
    javaclass = 'basicConstraintsExtDefaultImpl'
    result = common.check_policy(PolicySet, javaclass)

    if result is False:
        #Get Policy ID 
        pvalue = get_policyId(PolicySet)
        
        #Description
        Basic_Constraints_Extension_Default_description = 'This default populates a Basic Constraints Extension (2.5.29.19) to the request.,The default values are Criticality=true, Is CA=true, Path Length=-1'

        # Policy Value
        Policy_Value = etree.SubElement(PolicySet, 'value', id=pvalue)

        # Policy Definition
        Policy_definition = etree.SubElement(Policy_Value, 'def',
            id='Basic Constraints Extension Default',classId='basicConstraintsExtDefaultImpl')
        Policy_description = etree.SubElement(Policy_definition, 'description').text = Basic_Constraints_Extension_Default_description

        # Policy Attributes
        Basic_Constraints_Extension_Default_attributes = [
            ('basicConstraintsCritical', 'boolean', 'Criticality','false','NULL'),
            ('basicConstraintsIsCA', 'boolean', 'Is CA', 'true', 'NULL'),
            ('basicConstraintsPathLen', 'integer', 'Path Length', '-1', 'NULL')
            ]

        common.policy_attributes(Policy_definition, Basic_Constraints_Extension_Default_attributes)

        # Policy Parameters
        Basic_Constraints_Extension_Default_params = [
            ('basicConstraintsCritical', 'true'),
            ('basicConstraintsIsCA', isCA),
            ('basicConstraintsPathLen', PathLength)
            ]
        common.policy_parameters(Policy_definition, Basic_Constraints_Extension_Default_params)
        
        # Constraint Definition
        constraints.basicConstraintsCritical(Policy_Value,PathLength, isCA)

    else:
        Policy_Value = common.get_Element_PolicyValue(PolicySet, javaclass)
        basicConstraintsIsCA_params = Policy_Value.find('./def/params[@name="basicConstraintsIsCA"]')
        basicConstraintsIsCA_params[0].text = isCA
        basicConstraintsPathLen_params = Policy_Value.find('./def/params[@name="basicConstraintsPathLen"]')
        basicConstraintsPathLen_params[0].text = PathLength

        basicConstraintsIsCA_constraint = Policy_Value.find('./constraint/constraint[@id=basicConstraintsIsCA]/value')
        basicConstraintsIsCA_constraint.text = isCA
        basicConstraintsPathLen_constraint = Policy_Value.find('./constraint/constraint[@id="basicConstraintsMaxPathLen"]/value')
        basicConstraintsPathLen_constraint.text = PathLength


def Subject_Key_Identifier_Extension_Default(root,PolicySet):
    ''' This function defines Subject Key Identifier Extension Default Policy '''

    javaclass = 'subjectKeyIdentifierExtDefaultImpl'
    result = common.check_policy(PolicySet, javaclass)

    if result is False:
        # Get Policy ID 
        pvalue = get_policyId(PolicySet)
        # Description
        Subject_Key_Identifier_Extension_Default_description = 'This default populates a Subject Key Identifier Extension (2.5.29.14) to the request.'

        # Policy Value
        Policy_Value = etree.SubElement(PolicySet, 'value', id=pvalue)

        # Policy Definition
        Policy_definition = etree.SubElement(Policy_Value, 'def',
            id='Subject Key Identifier Extension Default', classId='subjectKeyIdentifierExtDefaultImpl')
        Policy_description = etree.SubElement(Policy_definition, 'description').text = Subject_Key_Identifier_Extension_Default_description

        # Policy Attributes
        Subject_Key_Identifier_Extension_Default_attributes = [
            ('critical', 'string', 'readonly', 'Criticality', 'NULL'),
            ('keyid', 'string', 'readonly', 'Key ID', 'NULL')]

        common.policy_attributes(Policy_definition, Subject_Key_Identifier_Extension_Default_attributes)
        # Policy Parameters
        # None

        # Constraint Definition
        constraints.noConstraintImpl(Policy_Value)
    else:
        Policy_Value = common.get_Element_PolicyValue(PolicySet, javaclass)

def Signing_Alg(root,PolicySet):

    ''' This Function defines Signing Algorithm Policy '''
    javaclass = 'signingAlgDefaultImpl'

    result = common.check_policy(PolicySet, javaclass)
    if result is False:

        #Get Policy ID 
        pvalue = get_policyId(PolicySet)

        #Description
        Signing_Alg_description = 'This default populates the Certificate Signing Algorithm. The default values are Algorithm=SHA512withRSA'

        # Policy Value
        Policy_Value = etree.SubElement(PolicySet, 'value', id=pvalue)

        #  Policy Definition
        Policy_definition = etree.SubElement(Policy_Value, 'def',
                id='Signing Alg', classId='signingAlgDefaultImpl')
        Policy_description = etree.SubElement(Policy_definition, 'description').text = Signing_Alg_description

        # Policy Attributes

        Signing_Alg_attributes = [('signingAlg', 'choice','SHA1withRSA,SHA256withRSA,SHA512withRSA,MD5withRSA,MD2withRSA', 
        'Signing Algorithm', 'NULL')]
        common.policy_attributes(Policy_definition, Signing_Alg_attributes)

        # Policy Parameters
        Signing_Alg_params = [('signingAlg', '-')]
        common.policy_parameters(Policy_definition, Signing_Alg_params)

        #Constraint
        constraints.signingAlgConstraintImpl(Policy_Value)

    else:
        Policy_Value = common.get_Element_PolicyValue(PolicySet, javaclass)



def AIA_Extension_Default(root,PolicySet):
    ''' This Function defines AIA Extension Default Policy '''

    javaclass = 'authInfoAccessExtDefaultImpl'
    result = common.check_policy(PolicySet, javaclass)

    if result is False:
        #Get Policy ID 
        pvalue = get_policyId(PolicySet)

        s1 = 'This default populates a Authority Info Access Extension (1.3.6.1.5.5.7.1.1) to the request. '
        s2 = 'The default values are Criticality=false,Record #0{Method:1.3.6.1.5.5.7.48.1,Location Type:URIName,Location:,Enable:true}'
        AIA_Extension_description = s1 + s2

        # Policy Value
        Policy_Value = etree.SubElement(PolicySet, 'value', id=pvalue)

        # Policy Definition
        Policy_definition = etree.SubElement(Policy_Value, 'def',
            id='AIA Extension Default', classId='authInfoAccessExtDefaultImpl')
        Policy_description = etree.SubElement(Policy_definition, 'description').text = AIA_Extension_description

        # Policy Attributes

        AIA_Extension_Default_attributes = [
            ('authInfoAccessCritical', 'boolean', 'NULL','Criticality','false'),
            ('authInfoAccessGeneralNames', 'string_list', 'NULL', 'General Names', 'NULL')]

        common.policy_attributes(Policy_definition, AIA_Extension_Default_attributes)

        # Policy Parameters
        AIA_Extension_Default_params = [
            ('authInfoAccessCritical','false'),
            ('authInfoAccessNumADs', '1'),
            ('authInfoAccessADMethod_0', '1.3.6.1.5.5.7.48.1'),
            ('authInfoAccessADLocationType_0', 'URIName'),
            ('authInfoAccessADLocation_0', ''),
            ('authInfoAccessADEnable_0', 'true')
            ]
        common.policy_parameters(Policy_definition, AIA_Extension_Default_params)

        # Constraint
        constraints.noConstraintImpl(Policy_Value)
    else:
        Policy_Value = common.get_Element_PolicyValue(PolicySet, javaclass)

def No_Default(root,PolicySet,notBefore,notAfter):

    javaclass = 'noDefaultImpl'
    result = common.check_policy(PolicySet, javaclass)

    if result is False:

        #Get Policy ID
        pvalue = get_policyId(PolicySet)

        # Description
        No_Default_description = 'No Default'


        # Policy Value
        Policy_Value = etree.SubElement(PolicySet, 'value', id=pvalue)

        #  Policy Definition
        Policy_definition = etree.SubElement(Policy_Value, 'def',
            id='No Default', classId='noDefaultImpl')
        Policy_description = etree.SubElement(Policy_definition, 'description').text = No_Default_description

        # Policy Attributes None
        # Policy Parameters None
    
        #constraint
        constraints.renewGracePeriodConstraintImpl(Policy_Value,notBefore,notAfter)

    else:
        Policy_Value = common.get_Element_PolicyValue(PolicySet, javaclass)
        NotBeforeDefaultValue = Policy_Value.find('./constraint[@id="Renewal Grace Period Constraint"]/constraint[@id="renewal.graceBefore"]/descriptor/DefaultValue')
        NotBeforeDefaultValue.text = notBefore
        NotBeforeValue = Policy_Value.find('./constraint[@id="Renewal Grace Period Constraint"]/constraint[@id="renewal.graceBefore"]/value')
        NotBeforeValue.text = notBefore
        
        NotAfterDefaultValue = Policy_Value.find('./constraint[@id="Renewal Grace Period Constraint"]/constraint[@id="renewal.graceAfter"]/descriptor/DefaultValue')
        NotAfterDefaultValue.text = notAfter
        NotAfterValue = Policy_Value.find('./constraint[@id="Renewal Grace Period Constraint"]/constraint[@id="renewal.graceAfter"]/value')
        NotAfterValue.text = notAfter


def Validity_Default(root, PolicySet, defaultRange, range_value):

    javaclass = 'validityDefaultImpl'
    result = common.check_policy(PolicySet, javaclass)

    if result is False:
        #Get Policy ID
        pvalue = get_policyId(PolicySet)

        #Description
        Validity_Default_description='This default populates a Certificate Validity to the request. The default values are Range=180 in days'

        # Policy Value
        Policy_Value = etree.SubElement(PolicySet, 'value', id=pvalue)

        # Policy Definition
        Policy_definition = etree.SubElement(Policy_Value, 'def',
            id='Validity Default', classId='validityDefaultImpl')
        Policy_description = etree.SubElement(Policy_definition, 'description').text = Validity_Default_description

        # Policy Attributes
        Validity_Default_attributes = [
            ('notBefore', 'string', 'NULL', 'Not Before', 'NULL'),
            ('notAfter', 'string', 'NULL', 'Not After', 'NULL')]

        common.policy_attributes(Policy_definition, Validity_Default_attributes)
        # Policy Parameters
        Validity_Default_params = [
            ('range', defaultRange),
            ('startTime', '0')]

        common.policy_parameters(Policy_definition, Validity_Default_params)

        #Constraint 
        constraints.validityConstraintImpl(Policy_Value, defaultRange, range_value)
    else:
        Policy_Value = common.get_Element_PolicyValue(PolicySet, javaclass)
        defaultRange_value = Policy_Value.find('./def/params[@name="range"]/value')
        defaultRange_value.text = defaultRange

        Constraint_DefaultValue = Policy_Value.find('./constraint[@id="Validity Constraint"]/constraint[@id="range"]/descriptor/DefaultValue')
        Constraint_DefaultValue.text = range_value
        Constraint_Value = Policy_Value.find('./constraint[@id="Validity Constraint"]/constraint[@id="range"]/value')
        Constraint_Value.text = range_value

def Extended_Key_Usage_Extension_Default(root,PolicySet):

    javaclass = 'extendedKeyUsageExtDefaultImpl'
    result = common.check_policy(PolicySet, javaclass)

    if result is False:

        #Get Policy ID
        pvalue = get_policyId(PolicySet)
        
        #Description
        s1 = 'This default populates an Extended Key Usage Extension () to the request.'
        s2 = 'The default values are Criticality=false, OIDs=1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4'
        Extended_Key_Usage_Extension_Default_Description = s1 + s2
    
        # policy Value
        Policy_Value = etree.SubElement(PolicySet, 'value', id=pvalue)

        # Policy Definition
        Policy_definition = etree.SubElement(Policy_Value, 'def',
            id='Extended Key Usage Extension Default', classId='extendedKeyUsageExtDefaultImpl')
        Policy_description = etree.SubElement(Policy_definition, 'description').text = Extended_Key_Usage_Extension_Default_Description

        # Policy Attributes
        Extended_Key_Usage_Extension_Default_attributes = [
            ('exKeyUsageCritical', 'boolean', 'NULL', 'Criticality', 'false'),
            ('exKeyUsageOIDs', 'string_list', 'NULL', 'Comma-Separated list of Object Identifiers', 'false')]

        common.policy_attributes(Policy_definition, Extended_Key_Usage_Extension_Default_attributes)

        # Policy Parameters
        Extended_Key_Usage_Extension_Default_params = [
            ('exKeyUsageCritical','false'),
            ('exKeyUsageOIDs', '1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4')]

        common.policy_parameters(Policy_definition, Extended_Key_Usage_Extension_Default_params)

        # Constraint
        constraints.noConstraintImpl(Policy_Value)
    else:
        Policy_Value = common.get_Element_PolicyValue(PolicySet, javaclass)

def Subject_Alt_Name_Constraint(root,PolicySet,altType,altPattern):

    javaclass = 'subjectAltNameExtDefaultImpl'
    result = common.check_policy(PolicySet, javaclass)

    if result is False:

        #Get Policy ID
        pvalue = get_policyId(PolicySet)

        #Description
        s1 = 'This default populates a Subject Alternative Name Extension (2.5.29.17) to the request.'
        s2 = 'The default values are Criticality=false, Record #0{Pattern:$request.requestor_email$,Pattern Type:RFC822Name,Enable:true}'
        Subject_Alt_Name_Constraint_description = s1 + s2

        # Policy Value
        Policy_Value = etree.SubElement(PolicySet, 'value', id=pvalue)

        # Policy Definition
        Policy_definition = etree.SubElement(Policy_Value, 'def',
            id='Subject Alt Name Constraint', classId='subjectAltNameExtDefaultImpl')
        Policy_description = etree.SubElement(Policy_definition, 'description').text = Subject_Alt_Name_Constraint_description

        # Policy Attributes
        Subject_Alt_Name_Constraint_attributes = [
            ('subjAltNameExtCritical', 'boolean', 'NULL', 'Criticality', 'false'),
            ('subjAltNames', 'string_list', 'NULL', 'General Names', 'NULL')]

        common.policy_attributes(Policy_definition, Subject_Alt_Name_Constraint_attributes)

        # Policy Parameters
        Subject_Alt_Name_Constraint_params = [
            ('subjAltNameExtCritical', 'false'),
            ('subjAltNameNumGNs', '1'),
            ('subjAltExtType_0', altType),
            ('subjAltExtPattern_0', altPattern),
            ('subjAltExtGNEnable_0', 'true')]

        common.policy_parameters(Policy_definition, Subject_Alt_Name_Constraint_params)

        # constraints
        constraints.noConstraintImpl(Policy_Value)
    else:
        Policy_Value = common.get_Element_PolicyValue(PolicySet, javaclass)
        subjAltExtType_0_param = Policy_Value.find('./def/params[@name="subjAltExtType_0"]/value')
        subjAltExtType_0_param.text = altType
        subjAltExtPattern_0_param = Policy_Value.find('./def/params[@name="subjAltExtPattern_0"]/value')
        subjAltExtPattern_0_param.text = altPattern


def Generic_Extension(root,PolicySet):

    javaclass = 'genericExtDefaultImpl'
    result = common.check_policy(PolicySet, javaclass)

    if result is False:
        #Get Policy ID
        pvalue = get_policyId(PolicySet)

        #Description
        s1 = 'This default populates a Generic Extension to the request. The default values are Criticality=, OID=1.2.840.113549.1.9.15,'
        s2 = ' OID=1.2.840.113549.1.9.15, Value=' 
        s3 = '3067300B06092A864886F70D010105300B06092A864886F70D01010B300B06092A864886F70D01010C300B06092A864886F70D01010D300A06082A864886F70D0307300B0609608648016503040102300B060960864801650304012A300B06092A864886F70D010101'
        Generic_Extension_description = s1 + s2 + s3

        # Policy Value
        Policy_Value = etree.SubElement(PolicySet, 'value', id=pvalue)

        # Policy Definition
        Policy_definition = etree.SubElement(Policy_Value, 'def',
            id='Generic Extension', classId='genericExtDefaultImpl')
        Policy_description = etree.SubElement(Policy_definition, 'description').text = Generic_Extension_description
        # Policy Attributes
        Generic_Extension_attributes = [
            ('genericExtCritical', 'boolean', 'NULL', 'Criticality', 'false'),
            ('genericExtData', 'string_list', 'NULL', 'Extension Value', 'NULL')]

        # Policy Parameters
        Generic_Extension_params = [
            ('genericExtCritical', ''),
            ('genericExtOID', '1.2.840.113549.1.9.15'),
            ('genericExtData', s3)]
        common.policy_parameters(Policy_definition, Generic_Extension_params)

        # Constraints
        constraints.noConstraintImpl(Policy_Value)
    else:
        Policy_Value = common.get_Element_PolicyValue(PolicySet, javaclass)

def Netscape_Certificate_Type_Extension_Default(root,PolicySet,extlist):

    javaclass = 'nsCertTypeExtDefaultImpl'
    result = common.check_policy(PolicySet, javaclass)

    if result is False:

        #Get Policy ID
        pvalue = get_policyId(PolicySet)

        # Description
        Netscape_Certificate_Type_Extension_Default_description = 'This default populates a Netscape Certificate Type Extension'

        # Policy Value
        Policy_Value = etree.SubElement(PolicySet, 'value', id=pvalue)

        # Policy Definition
        Policy_definition = etree.SubElement(Policy_Value, 'def',
             id='Netscape Certificate Type Extension Default', classId='nsCertTypeExtDefaultImpl')
        Policy_description = etree.SubElement(Policy_definition, 'description').text =  Netscape_Certificate_Type_Extension_Default_description
    
        # Policy Attributes
        Netscape_Certificate_Type_Extension_Default_attributes = [
            ('nsCertCritical', 'boolean', 'NULL', 'Criticality','false'),
            ('nsCertSSLClient', 'boolean', 'NULL', 'SSL Client', 'false'),
            ('nsCertSSLServer', 'boolean', 'NULL', 'SSL Server', 'false'),
            ('nsCertEmail', 'boolean', 'NULL', 'Email', 'false'),
            ('nsCertObjectSigning', 'boolean', 'NULL', 'Object Signing', 'false'),
            ('nsCertSSLCA', 'boolean', 'NULL', 'SSL CA', 'false'),
            ('nsCertEmailCA', 'boolean', 'NULL', 'Email CA', 'false'),
            ('nsCertObjectSigningCA', 'boolean', 'NULL', 'Object Signing CA', 'false')]

        # Policy Parameters
        Netscape_Certificate_Type_Extension_Default_params = [
            ('nsCertCritical', common.check_ext_key_usage(extlist, 'nsCertCritical')),
            ('nsCertSSLClient', common.check_ext_key_usage(extlist, 'nsCertSSLClient')),
            ('nsCertSSLServer', common.check_ext_key_usage(extlist, 'nsCertSSLServer')),
            ('nsCertEmail', common.check_ext_key_usage(extlist, 'nsCertEmail')),
            ('nsCertObjectSigning', common.check_ext_key_usage(extlist, 'nsCertObjectSigning')),
            ('nsCertSSLCA', common.check_ext_key_usage(extlist, 'nsCertSSLCA')),
            ('nsCertEmailCA', common.check_ext_key_usage(extlist, 'nsCertEmailCA')),
            ('nsCertObjectSigningCA', common.check_ext_key_usage(extlist, 'nsCertObjectSigningCA'))]

        common.policy_parameters(Policy_definition, Netscape_Certificate_Type_Extension_Default_params)

        # Constraints
        constraints.noConstraintImpl(Policy_Value)
    else:
        Policy_Value = common.get_Element_PolicyValue(PolicySet, javaclass)
        for v in extlist:
            result = Policy_Value.find("./def/params[@name=\"%s\"]" % v)
            result[0].text = 'true'

def crl_Distribution_Points_Ext_Default(root,PolicySet,crlurl):

    javaclass = 'crlDistributionPointsExtDefaultImpl'
    result = common.check_policy(PolicySet, javaclass)
    
    if result is False:

        #Get Policy ID
        pvalue = get_policyId(PolicySet)

        #Description
        s1='This default populates a CRL Distribution Points Extension (2.5.29.31) to the request'
        s2='The default values are Criticality=false, Record #0{Point Type:URIName,Point Name:http://localhost.localdomain:9180/ca/ee/ca/getCRL'
        s3='?crlIssuingPoint=MasterCRL&amp;op=getCRL&amp;crlDisplayType=cachedCRL&amp;submit=Submit,Reasons:,Issuer Type'
        s4=':,Issuer Name:,Enable:true}'
        clrDistribution_Point_Name = 'http://localhost.localdomain:9180/ca/ee/ca/getCRL?crlIssuingPoint=MasterCRL&amp;op=getCRL&amp;crlDisplayType=cachedCRL&amp;submit=Submit'

        # Policy Value
        Policy_Value = etree.SubElement(PolicySet, 'value', id=pvalue)

        Policy_definition = etree.SubElement(Policy_Value, 'def',
                id='crlDistributionPointsExtDefaultImpl', classId='crlDistributionPointsExtDefaultImpl')
        Policy_description = etree.SubElement(Policy_definition, 'description').text = s1 + s2 + s3 + s4

        # Policy Attributes
        crl_Distribution_Points_Ext_Default_attributes = [
                ('crlDistPointsCritical', 'boolean', 'NULL', 'Criticality', 'false'),
                ('crlDistPointsValue', 'string_list', 'NULL', 'CRL Distribution Points', 'NULL')]
        # Params
        crl_Distribution_Points_Ext_Default_params = [
                ('crlDistPointsNum', '1'),
                ('crlDistPointsPointType_0', 'URIName'),
                ('crlDistPointsPointName_0', crlurl),
                ('crlDistPointsReasons_0', 'NULL'),
                ('crlDistPointsIssuerType_0', 'NULL'),
                ('crlDistPointsIssuerName_0', 'NULL'),
                ('crlDistPointsEnable_0', 'true')]
        common.policy_parameters(Policy_definition, crl_Distribution_Points_Ext_Default_params)

        #No Constraint
        constraints.noConstraintImpl(Policy_Value)
    else:
        Policy_Value = common.get_Element_PolicyValue(PolicySet, javaclass)
        crlDistPointsPointName_value = Policy_Value.find('./def/params[@name="crlDistPointsPointName_0"]/value')
        crlDistPointsPointName_value[0].text = crlurl

def User_Supplied_Extension_Default(root,PolicySet,ExtOID):

    javaclass = 'userExtensionDefaultImpl'
    result = common.check_policy(PolicySet, javaclass)

    if result is False:
        # Get Policy ID
        pvalue = get_policyId(PolicySet)

        # Description
        s1 = 'This default populates a User-Supplied Extension (%s) to the request.', ExtOID

        # Policy Value
        Policy_Value = etree.SubElement(PolicySet, 'value', id=pvalue)

        # Policy Definition
        Policy_definition = etree.SubElement(Policy_Value, 'def',
                id='User Supplied Extension Default', classid='userExtensionDefaultImpl')
        Policy_description = etree.SubElement(Policy_definition, 'description').text = s1

        # Policy Attributes
        User_Supplied_Extension_Default_attributes = [('userExtOID', 'string', 'readonly', 'Object Identifier', 'NULL')]

        # Policy Params
        User_Supplied_Extension_Default_params = [('userExtOID', ExtOID)]
        common.policy_parameters(Policy_definition, User_Supplied_Extension_Default_params)

        # No Constraint
        constraints.noConstraintImpl(Policy_Value)
    else:
        Policy_Value = common.get_Element_PolicyValue(PolicySet, javaclass)
        userExtOID_param = Policy_Value.find('./def/params[@name="userExtOID"]/value')
        userExtOID_param.text = ExtOID
