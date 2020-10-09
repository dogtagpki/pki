# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2017 Red Hat, Inc. All rights reserved.
#
#   This copyrighted material is made available to anyone wishing
#   to use, modify, copy, or redistribute it subject to the terms
#   and conditions of the GNU General Public License version 2.
#
#   This program is distributed in the hope that it will be
#   useful, but WITHOUT ANY WARRANTY; without even the implied
#   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
#   PURPOSE. See the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public
#   License along with this program; if not, write to the Free
#   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
#   Boston, MA 02110-1301, USA.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

from lxml import etree
import tempfile
import os


class Common(object):
    ''' This class defines some generic methods required for Policy class '''

    @classmethod
    def check_policy(cls, policy_set_element, javaclass):
        '''
        Check if a given policy already exists
        :params etree.ElementTree policy_set_element: policyset element of profile xml
        :params str javaclass: java class to be searched

        :Returns bool: True if javaclass is found else returns False
        '''
        defined_policies = policy_set_element.findall("./value/def")
        list_of_policy_classes = []
        for classes in defined_policies:
            list_of_policy_classes.append(classes.get('classId'))

        # check if my classId is already there
        if javaclass in list_of_policy_classes:
            return True
        else:
            return False

    @classmethod
    def get_policy_id(cls, policy_set_element):
        '''
        Returns the current policy id(value) in a particular profile
        :params etree.ElementTree policy_set_element: Current policy element

        :Returns str PolicyValue: current(last assigned) policy value.
        '''
        policy_value = '1'
        if len(policy_set_element) > 1:
            policy_value = '1'
            for valuedef in policy_set_element.iterchildren(tag='value'):
                value = valuedef.get('id')

            policy_value = int(value) + 1
            return str(policy_value)
        else:
            return policy_value

    @classmethod
    def get_element_policy_value(cls, policy_set_element, javaclass):
        '''
        Get the element which displays the current policy element
        :params etree.ElementTree policy_set_element: Current policy element
        :params str javaclass: java class name which implements
        '''
        mydict = {}
        for key in policy_set_element.iterchildren(tag='value'):
            PolicyValues = key.items()[0][1]
            classId = key[0].get('classId')
            mydict[classId] = PolicyValues

        if javaclass in mydict:
            value_Id = mydict[javaclass]
            Policy_Value = policy_set_element.find(
                './value[@id=' + "\"" + str(value_Id) + "\"" + "]")
            return Policy_Value
        else:
            return None

    @classmethod
    def check_ext_key_usage(cls, mylist, string):

        s1 = 'true'
        s2 = 'false'
        if string in mylist:
            return s1
        else:
            return s2


class Constraints(object):
    ''' This class defines all the constraints used in policies '''

    @classmethod
    def constraint_attributes(cls, constraint_definition, constraint_attributes):
        '''
        Set constraint attributes to a constraint
        :params str constraint_definition: Brief description of the constraint
        :params str constraint_attributes: Attributes to be used by the constraint
        '''
        for idx, (constraintid, syntax, constraint,
                  description, defaultvalue, value) in enumerate(constraint_attributes):
            constraint_id = etree.SubElement(
                constraint_definition, 'constraint', id=constraintid)
            constraint_id_descriptor = etree.SubElement(
                constraint_id, 'descriptor')
            constraint_id_descriptor_syntax = etree.SubElement(
                constraint_id_descriptor, 'Syntax').text = syntax
            if constraint != 'NULL':
                constraint_id_descriptor_syntax = etree.SubElement(
                    constraint_id_descriptor, 'Constraint').text = constraint
            constraint_id_descriptor_description = etree.SubElement(
                constraint_id_descriptor, 'Description').text = description
            if defaultvalue != 'NULL':
                constraint_id_descriptor_defaultvalue = etree.SubElement(
                    constraint_id_descriptor, 'DefaultValue').text = defaultvalue
            if value != 'NULL':
                constraint_value = etree.SubElement(
                    constraint_id, 'value').text = value
            else:
                constraint_value = etree.SubElement(constraint_id, 'value')

    @classmethod
    def validityConstraintImpl(cls, policy_value, default_value, range_value):
        '''
        This method defines the validity constraint in the profile.
        :params str policy_value:  Current policy value
        :params str default_value: Default policy value
        :params str range_value: Validity range of the cert

        :Returns None
        '''
        constraint_definition = etree.SubElement(
            policy_value,
            'constraint',
            id='Validity Constraint')
        s1 = 'This constraint rejects the validity that is not between %s days.' % (
            range_value)
        constraint_description = etree.SubElement(
            constraint_definition, 'description').text = s1
        constraint_classid = etree.SubElement(
            constraint_definition, 'classId').text = 'validityConstraintImpl'

        validityConstraintImpl_attributes = [
            ('range', 'integer', 'NULL', 'Validity Range (in days)',
             str(default_value), str(range_value)),
            ('notBeforeGracePeriod', 'integer', 'NULL',
             'Grace period for Not Before being set in the future (in seconds).',
             '0', 'NULL'),
            ('notBeforeCheck', 'boolean', 'NULL', 'Check Not Before against current time',
             'false', 'false'),
            ('notAfterCheck', 'boolean', 'NULL', 'Check Not After against Not Before',
             'false', 'false')]
        cls.constraint_attributes(
            constraint_definition, validityConstraintImpl_attributes)

    @classmethod
    def subjectNameConstraintImpl(cls, policy_value, subject_pattern):
        '''
        Implements Subject Name Constraint
        :params str policy_value:  Current policy value
        :params str subject_pattern: Subject pattern to be used in the constraint

        :Returns None
        '''
        constraint_definition = etree.SubElement(policy_value,
                                                 'constraint', id='Subject Name Constraint')
        constraint_description = etree.SubElement(constraint_definition,
                                                  'description').text = 'This constraint accepts the subject name that matches ' + subject_pattern
        constraint_classid = etree.SubElement(
            constraint_definition, 'classId').text = 'subjectNameConstraintImpl'
        subjectNameConstraintImpl_attributes = [
            ('pattern', 'string', 'NULL', 'Subject Name Pattern', 'NULL', subject_pattern)]
        cls.constraint_attributes(
            constraint_definition, subjectNameConstraintImpl_attributes)

    @classmethod
    def noConstraintImpl(cls, policy_value):
        '''
        Implements noConstraint policy
        :params str policy_value:  Current policy value

        :Returns None
        '''
        constraint_definition = etree.SubElement(
            policy_value, 'constraint', id='No Constraint')
        constraint_description = etree.SubElement(
            constraint_definition, 'description').text = 'No Constraint'
        constraint_classid = etree.SubElement(
            constraint_definition, 'classId').text = 'noConstraintImpl'

    @classmethod
    def basicConstraintsCritical(cls, policy_value, path_length, isCA):

        constraint_definition = etree.SubElement(policy_value,
                                                 'constraint', id='Basic Constraint Extension Constraint')
        s1 = "This constraint accepts the Basic Constraint extension, " + \
            "if present, only when Criticality=true,"
        s2 = 'Is CA=true, Min Path Length=-1, Max Path Length=-1'
        constraint_description = etree.SubElement(
            constraint_definition, 'description').text = s1 + s2
        constraint_classid = etree.SubElement(constraint_definition,
                                              'classId').text = 'basicConstraintsExtConstraintImpl'

        basicConstraintsCritical_attributes = [
            ('basicConstraintsCritical', 'choice',
             'true,false,-', 'Criticality', '-', 'true'),
            ('basicConstraintsIsCA', 'choice',
             'true,false,-', 'Is CA', '-', isCA),
            ('basicConstraintsMinPathLen', 'integer',
             'NULL', 'Min Path Length', '-1', path_length),
            ('basicConstraintsMaxPathLen', 'integer',
             'NULL', 'Max Path Length', '100', '100')
        ]
        cls.constraint_attributes(
            constraint_definition, basicConstraintsCritical_attributes)

    @classmethod
    def signingAlgConstraintImpl(cls, policy_value):

        constraint_definition = etree.SubElement(
            policy_value, 'constraint', id='No Constraint')
        s1 = 'This constraint accepts only the Signing Algorithms of SHA1withRSA,SHA256withRSA,SHA512withRSA,'
        s2 = 'SHA1withDSA,SHA1withEC,SHA256withEC,SHA384withEC,SHA512withEC,SHA256withRSA/PSS,SHA384withRSA/PSS,' \
             'SHA512withRSA/PSS'
        constraint_description = etree.SubElement(
            constraint_definition, 'description').text = s1 + s2
        constraint_classid = etree.SubElement(
            constraint_definition, 'classId').text = 'signingAlgConstraintImpl'

        signingAlgConstraintImpl_attributes = [
            ('signingAlgsAllowed', 'string', 'NULL', 'Allowed Signing Algorithms',
             "SHA1withRSA,SHA1withDSA,SHA256withRSA," +
             "SHA512withRSA,SHA1withEC,SHA256withEC,SHA384withEC,SHA512withEC",
             "SHA1withRSA,SHA256withRSA,SHA512withRSA," +
             "SHA1withEC,SHA256withEC,SHA384withEC,SHA512withEC,SHA256withRSA/PSS,SHA384withRSA/PSS,"
             "SHA512withRSA/PSS")
        ]
        cls.constraint_attributes(
            constraint_definition, signingAlgConstraintImpl_attributes)

    @classmethod
    def renewGracePeriodConstraintImpl(cls, policy_value, not_before, not_after):

        constraint_definition = etree.SubElement(policy_value, 'constraint',
                                                 id='Renewal Grace Period Constraint')
        s1 = 'This constraint rejects the validity that is not between %s days before' % (
            not_before)
        s2 = 'and %s days after original cert expiration date days.' % (
            not_after)
        constraint_description = etree.SubElement(
            constraint_definition, 'description').text = s1 + s2
        constraint_classid = etree.SubElement(
            constraint_definition, 'classId').text = 'renewGracePeriodConstraintImpl'

        renewGracePeriodConstraintImpl_attributes = [
            ('renewal.graceBefore', 'integer', 'NULL',
             'Renewal Grace Period Before', not_before, not_before),
            ('renewal.graceAfter', 'integer', 'NULL', 'Renewal Grace Period After', not_after, not_after)]

        cls.constraint_attributes(
            constraint_definition, renewGracePeriodConstraintImpl_attributes)

    @classmethod
    def keyUsageExtConstraintImpl(cls, policy_value, keylist):

        constraint_definition = etree.SubElement(
            policy_value, 'constraint', id='Key Usage Extension Constraint')
        definition = "This constraint accepts the Key Usage extension, if present,"\
            "only when Criticality=true, Digital Signature=true," + \
            "Non-Repudiation=true, Key Encipherment=true, Data Encipherment=false,'" + \
            "Key Agreement=false, Key Certificate Sign=false, Key CRL Sign=false, " + \
            "Encipher Only=false, Decipher Only=false"

        constraint_description = etree.SubElement(
            constraint_definition, 'description').text = definition
        constraint_classid = etree.SubElement(
            constraint_definition, 'classId').text = 'keyUsageExtConstraintImpl'

        key_default_list = (
            'keyUsageCritical', 'keyUsageDigitalSignature', 'keyUsageNonRepudiation',
            'keyUsageKeyEncipherment', 'keyUsageDataEncipherment', 'keyUsageKeyAgreement',
            'keyUsageKeyCertSign', 'keyUsageCrlSign', 'keyUsageEncipherOnly',
            'keyUsageDecipherOnly')

        keyUsageExtConstraintImpl_attributes = [
            (key_default_list[0], 'choice', 'true,false,-', 'Criticality', '-',
             Common.check_ext_key_usage(keylist, key_default_list[0])),
            (key_default_list[1], 'choice', 'true,false,-', 'Digital Signature', '-',
             Common.check_ext_key_usage(keylist, key_default_list[1])),
            (key_default_list[2], 'choice', 'true,false,-', 'Non-Repudiation', '-',
             Common.check_ext_key_usage(keylist, key_default_list[2])),
            (key_default_list[3], 'choice', 'true,false,-', 'Key Encipherment', '-',
             Common.check_ext_key_usage(keylist, key_default_list[3])),
            (key_default_list[4], 'choice', 'true,false,-', 'Data Encipherment', '-',
             Common.check_ext_key_usage(keylist, key_default_list[4])),
            (key_default_list[5], 'choice', 'true,false,-', 'Key Agreement', '-',
             Common.check_ext_key_usage(keylist, key_default_list[5])),
            (key_default_list[6], 'choice', 'true,false,-', 'Key CertSign', '-',
             Common.check_ext_key_usage(keylist, key_default_list[6])),
            (key_default_list[7], 'choice', 'true,false,-', 'CRL Sign', '-',
             Common.check_ext_key_usage(keylist, key_default_list[7])),
            (key_default_list[8], 'choice', 'true,false,-', 'Encipher Only', '-',
             Common.check_ext_key_usage(keylist, key_default_list[8])),
            (key_default_list[9], 'choice', 'true,false,-', 'Decipher Only', '-',
             Common.check_ext_key_usage(keylist, key_default_list[9]))]
        cls.constraint_attributes(
            constraint_definition, keyUsageExtConstraintImpl_attributes)

    @classmethod
    def keyConstraintImpl(cls, policy_value):

        constraint_definition = etree.SubElement(policy_value, 'constraint',
                                                 id='Key Constraint')
        s1 = "This constraint accepts the key only if Key Type=-, " + \
            "Key Parameters =1024,2048,3072,4096,nistp256,nistp384,nistp521"
        constraint_description = etree.SubElement(
            constraint_definition, 'description').text = s1
        constraint_classid = etree.SubElement(
            constraint_definition, 'classId').text = 'keyConstraintImpl'
        s2 = "Key Lengths or Curves. For EC use comma separated list of curves, " + \
            "otherise use list of key sizes. Ex: 1024,2048,4096,8192 or:" + \
            "nistp256,nistp384,nistp521,sect163k1,nistk163 for EC."

        keyConstraintImpl_attributes = [
            ('keyType', 'choice', '-,RSA,EC', 'Key Type', 'RSA', '-'),
            ('keyParameters', 'string', 'NULL', s2, 'NULL',
             '1024,2048,3072,4096,nistp256,nistp384,nistp521')]

        cls.constraint_attributes(
            constraint_definition, keyConstraintImpl_attributes)


class Policy(object):
    ''' This class defines policies used in a profile '''

    @classmethod
    def add_policy_attributes(cls, policy_definition, policy_attributes):
        '''
        Set Policy Attributes to a policy definition
        '''
        for idx, (name, syntax, constraint, description, defaultvalue) in enumerate(policy_attributes):
            policy_attribute_name = etree.SubElement(
                policy_definition, 'policyAttribute', name=name)
            policy_attribute_descriptor = etree.SubElement(
                policy_attribute_name, 'Descriptor')
            policy_attribute_syntax = etree.SubElement(
                policy_attribute_descriptor, 'Syntax').text = syntax
            if constraint != 'NULL':
                policy_attribute_constraint = etree.SubElement(
                    policy_attribute_descriptor, 'Constraint').text = constraint
            policy_attribute_description = etree.SubElement(
                policy_attribute_descriptor, 'Description').text = description
            if defaultvalue != 'NULL':
                policy_attribute_defaultvalue = etree.SubElement(
                    policy_attribute_descriptor, 'DefaultValue').text = defaultvalue
            else:
                policy_attribute_defaultvalue = etree.SubElement(
                    policy_attribute_descriptor, 'DefaultValue')

    @classmethod
    def add_policy_parameters(cls, policy_definition, parameters):
        '''
        Set Policy parameters
        '''
        for idx, (name, value) in enumerate(parameters):
            policy_param_name = etree.SubElement(
                policy_definition, 'params', name=name)
            if value != 'NULL':
                #print("Value =",value)
                policy_param_value = etree.SubElement(
                    policy_param_name, 'value').text = str(value)
            else:
                policy_param_value = etree.SubElement(
                    policy_param_name, 'value')

    @classmethod
    def subject_name_default(cls, root_element, policy_set_element, subject_pattern, subject_default):
        '''
        Set Policy SubjectNameDefault
        '''
        javaclass = 'userSubjectNameDefaultImpl'
        result = Common.check_policy(policy_set_element, javaclass)
        if not result:
            # Get PolicyID
            pvalue = Common.get_policy_id(policy_set_element)
            Subject_Name_Default_description = "This default populates a User-Supplied" + \
                "Certificate Subject Name to the request"

            # Policy value
            Policy_Value = etree.SubElement(
                policy_set_element, 'value', id=pvalue)

            if subject_default:
                Policy_definition = etree.SubElement(Policy_Value, 'def',
                                                     classId='subjectNameDefaultImpl', id='Subject Name Default')
            else:
                Policy_definition = etree.SubElement(Policy_Value, 'def',
                                                     classId='userSubjectNameDefaultImpl', id='Subject Name Default')
            Policy_description = etree.SubElement(Policy_definition,
                                                  'description').text = Subject_Name_Default_description
            # Policy Attributes
            Subject_Name_Default_attributes = [
                ('name', 'string', 'NULL', 'Subject Name', 'NULL')]
            cls.add_policy_attributes(
                Policy_definition, Subject_Name_Default_attributes)

            # policy Parameters
            if subject_default:
                Subject_Name_Default_params = [('name', subject_default)]
                cls.add_policy_parameters(
                    Policy_definition, Subject_Name_Default_params)

            # policy constraints
            Constraints.subjectNameConstraintImpl(
                Policy_Value, subject_pattern)
        else:
            Policy_Value = Common.get_element_policy_value(
                policy_set_element, javaclass)
            if subject_default:
                Policy_Definition = Policy_Value[0]
                Policy_Definition.set('classId', 'subjectNameDefaultImpl')
                policy_param_name = etree.SubElement(
                    Policy_Definition, 'params', name='name')
                policy_param_value = etree.SubElement(
                    policy_param_name, 'value').text = subject_default
            if subject_pattern:
                CurrentValue = Policy_Value.find(
                    './constraint/constraint/value')
                CurrentValue.text = subject_pattern

    @classmethod
    def key_usage_default(cls, root, policy_set_element, keylist):
        ''' This function defines Key Usage Default Policy '''
        javaclass = 'keyUsageExtDefaultImpl'
        result = Common.check_policy(policy_set_element, javaclass)
        if not result:
            # Get policy ID
            pvalue = Common.get_policy_id(policy_set_element)
            Key_Usage_Default_description = "This default populates a Key Usage Extension (2.5.29.15) to the request," + \
                "The default values are Criticality=true Digital Signature=true," + \
                "Non-Repudiation=true,Key Encipherment=true, Data Encipherment=false, Key Agreement=false" + \
                "Key Certificate Sign=false, Key CRL Sign=false, Encipher Only=false, Decipher Only=false"
            Policy_Value = etree.SubElement(
                policy_set_element, 'value', id=pvalue)
            # Policy Definition
            Policy_definition = etree.SubElement(Policy_Value, 'def',
                                                 id='Key Usage Default', classId='keyUsageExtDefaultImpl')
            Policy_description = etree.SubElement(
                Policy_definition, 'description').text = Key_Usage_Default_description
            # Policy Attributes
            # #name,syntax,constraint,description,defaultvalue
            Key_Usage_Default_attributes = [
                ('keyUsageCritical', 'boolean', 'NULL', 'Criticality', 'false'),
                ('keyUsageDigitalSignature', 'boolean',
                 'NULL', 'Digital Signature', 'false'),
                ('keyUsageNonRepudiation', 'boolean',
                 'NULL', 'Non-Repudiation', 'false'),
                ('keyUsageKeyEncipherment', 'boolean',
                 'NULL', 'Key Encipherment', 'false'),
                ('keyUsageDataEncipherment', 'boolean',
                 'NULL', 'Data Encipherment', 'false'),
                ('keyUsageKeyAgreement', 'boolean',
                 'NULL', 'Key Agreement', 'false'),
                ('keyUsageKeyCertSign', 'boolean',
                 'NULL', 'Key CertSign', 'false'),
                ('keyUsageCrlSign', 'boolean', 'NULL', 'CRL Sign', 'false'),
                ('keyUsageEncipherOnly', 'boolean',
                 'NULL', 'Encipher Only', 'false'),
                ('keyUsageDecipherOnly', 'boolean', 'NULL', 'Decipher Only', 'false')]
            cls.add_policy_attributes(
                Policy_definition, Key_Usage_Default_attributes)
            # Policy parameters
            Key_Usage_Default_params = [
                ('keyUsageCritical', Common.check_ext_key_usage(
                    keylist, 'keyUsageCritical')),
                ('keyUsageDigitalSignature', Common.check_ext_key_usage(
                    keylist, 'keyUsageDigitalSignature')),
                ('keyUsageNonRepudiation', Common.check_ext_key_usage(
                    keylist, 'keyUsageNonRepudiation')),
                ('keyUsageKeyEncipherment', Common.check_ext_key_usage(
                    keylist, 'keyUsageKeyEncipherment')),
                ('keyUsageDataEncipherment', Common.check_ext_key_usage(
                    keylist, 'keyUsageDataEncipherment')),
                ('keyUsageKeyAgreement', Common.check_ext_key_usage(
                    keylist, 'keyUsageKeyAgreement')),
                ('keyUsageKeyCertSign', Common.check_ext_key_usage(
                    keylist, 'keyUsageKeyCertSign')),
                ('keyUsageCrlSign', Common.check_ext_key_usage(
                    keylist, 'keyUsageCrlSign')),
                ('keyUsageEncipherOnly', Common.check_ext_key_usage(
                    keylist, 'keyUsageEncipherOnly')),
                ('keyUsageDecipherOnly', Common.check_ext_key_usage(keylist, 'keyUsageDecipherOnly'))]

            cls.add_policy_parameters(
                Policy_definition, Key_Usage_Default_params)

            # policy constraint
            Constraints.keyUsageExtConstraintImpl(Policy_Value, keylist)
        else:
            Policy_Value = Common.get_element_policy_value(
                policy_set_element, javaclass)
            # Change Policy Parameters
            mylist = re.split(',', keylist)
            for v in mylist:
                result_param = Policy_Value.find(
                    "./def/params[@name=\"%s\"]/value" % v)
                result_param.text = 'true'
            # Change Policy Constraints
            for v in mylist:
                result_constraint = Policy_Value.find(
                    "./constraint/constraint[@id=\"%s\"]/value" % v)
                result_constraint.text = 'true'

    @classmethod
    def ca_certificate_validity_default(cls, root, policy_set_element):

        javaclass = 'caValidityDefaultImpl'
        result = Common.check_policy(policy_set_element, javaclass)
        if not result:
            # Get Policy ID
            pvalue = Common.get_policy_id(policy_set_element)
            CA_Certificate_description = '''
            This default populates a Certificate Validity to the request. \
            The default values are Range=7305 in days
            '''
            # Policy Value
            Policy_Value = etree.SubElement(
                policy_set_element, 'value', id=pvalue)

            # Policy Definition
            Policy_definition = etree.SubElement(Policy_Value, 'def',
                                                 id='CA Certificate Validity Default', classId='caValidityDefaultImpl')
            Policy_description = etree.SubElement(
                Policy_definition, 'description').text = CA_Certificate_description

            # policy Attributes
            CA_Certificate_Validity_Default_attributes = [
                ('notBefore', 'string', 'NULL', 'Not Before', 'NULL'),
                ('notAfter', 'string', 'NULL', 'notAfter', 'NULL'),
                ('bypassCAnotafter', 'boolean', 'NULL', 'Bypass CA notAfter constraint', 'false')]
            cls.add_policy_attributes(
                Policy_definition, CA_Certificate_Validity_Default_attributes)

            # Policy Parameters
            CA_Certificate_Validity_Default_params = [
                ('range', '7305'),
                ('startTime', '0'),
                ('bypassCAnotafter', '')]
            cls.add_policy_parameters(
                Policy_definition, CA_Certificate_Validity_Default_params)
            # Policy Constraint
            Constraints.validityConstraintImpl(Policy_Value, 365, 7305)
        else:
            Policy_Value = Common.get_element_policy_value(
                policy_set_element, javaclass)

    @classmethod
    def key_default(cls, root, policy_set_element):
        ''' This function Defines key default policy'''
        javaclass = 'userKeyDefaultImpl'
        result = Common.check_policy(policy_set_element, javaclass)
        if not result:
            # Get policy ID
            pvalue = Common.get_policy_id(policy_set_element)

            # Description
            Key_Default_description = 'This default populates a User-Supplied Certificate Key to the request'

            # Policy Value
            Policy_Value = etree.SubElement(
                policy_set_element, 'value', id=pvalue)

            # Policy Defintion
            Policy_definition = etree.SubElement(
                Policy_Value, 'def', id='Key Default', classId='userKeyDefaultImpl')
            Policy_description = etree.SubElement(
                Policy_definition, 'description').text = Key_Default_description

            # policy attributes
            Key_Default_attributes = [
                ('TYPE', 'string', 'readonly', 'Key Type', 'NULL'),
                ('LEN', 'string', 'readonly', 'Key Length', 'NULL'),
                ('KEY', 'string', 'readonly', 'Key', 'NULL')]
            cls.add_policy_attributes(
                Policy_definition, Key_Default_attributes)
            Constraints.keyConstraintImpl(Policy_Value)
        else:
            Policy_Value = Common.get_element_policy_value(
                policy_set_element, javaclass)

    @classmethod
    def authority_key_identifier_default(cls, root, policy_set_element):
        ''' This function Defines Authority Key Identifier Default Policy'''
        javaclass = 'authorityKeyIdentifierExtDefaultImpl'
        result = Common.check_policy(policy_set_element, javaclass)
        if not result:
            # Get Policy ID
            pvalue = Common.get_policy_id(policy_set_element)

            # Description
            Authority_Key_Identifier_Default_description = 'This default populates an Authority Key Identifier Extension (2.5.29.35) to the request.'

            # policy value
            Policy_Value = etree.SubElement(
                policy_set_element, 'value', id=pvalue)
            # Policy Definition
            Policy_definition = etree.SubElement(Policy_Value, 'def',
                                                 id='Authority Key Identifier Default',
                                                 classId='authorityKeyIdentifierExtDefaultImpl')
            Policy_description = etree.SubElement(
                Policy_definition, 'description').text = Authority_Key_Identifier_Default_description

            # Policy Attributes
            Authority_Key_Identifier_Default_attributes = [
                ('critical', 'string', 'readonly', 'Criticality', 'NULL'),
                ('keyid', 'string', 'readonly', 'Key ID', 'NULL')]

            cls.add_policy_attributes(
                Policy_definition, Authority_Key_Identifier_Default_attributes)

            # Constraint Definition
            Constraints.noConstraintImpl(Policy_Value)
        else:
            Policy_Value = Common.get_element_policy_value(
                policy_set_element, javaclass)

    @classmethod
    def basic_constraints_extension_default(cls, root, policy_set_element, pathlength, isCA):
        ''' This function Defines Basic Constraints Extension Default Policy'''
        javaclass = 'basicConstraintsExtDefaultImpl'
        result = Common.check_policy(policy_set_element, javaclass)

        if not result:
            # Get Policy ID
            pvalue = Common.get_policy_id(policy_set_element)

            # Description
            Basic_Constraints_Extension_Default_description = "This default populates a" + \
                "Basic Constraints Extension (2.5.29.19) to the request., " + \
                "The default values are Criticality=true, Is CA=true, Path Length=-1"
            # Policy Value
            Policy_Value = etree.SubElement(
                policy_set_element, 'value', id=pvalue)

            # Policy Definition
            Policy_definition = etree.SubElement(Policy_Value, 'def',
                                                 id='Basic Constraints Extension Default', classId='basicConstraintsExtDefaultImpl')
            Policy_description = etree.SubElement(Policy_definition,
                                                  'description').text = Basic_Constraints_Extension_Default_description

            # Policy Attributes
            Basic_Constraints_Extension_Default_attributes = [
                ('basicConstraintsCritical', 'boolean',
                 'Criticality', 'false', 'NULL'),
                ('basicConstraintsIsCA', 'boolean', 'Is CA', 'true', 'NULL'),
                ('basicConstraintsPathLen', 'integer', 'Path Length', '-1', 'NULL')]
            cls.add_policy_attributes(
                Policy_definition, Basic_Constraints_Extension_Default_attributes)

            # Policy Parameters
            Basic_Constraints_Extension_Default_params = [
                ('basicConstraintsCritical', 'true'),
                ('basicConstraintsIsCA', isCA),
                ('basicConstraintsPathLen', pathlength)]
            cls.add_policy_parameters(
                Policy_definition, Basic_Constraints_Extension_Default_params)

            # Constraint Definition
            Constraints.basicConstraintsCritical(
                Policy_Value, pathlength, isCA)

        else:
            Policy_Value = Common.get_element_policy_value(
                policy_set_element, javaclass)
            basicConstraintsIsCA_params = Policy_Value.find(
                './def/params[@name="basicConstraintsIsCA"]')
            basicConstraintsIsCA_params[0].text = isCA
            basicConstraintsPathLen_params = Policy_Value.find(
                './def/params[@name="basicConstraintsPathLen"]')
            basicConstraintsPathLen_params[0].text = pathlength

            basicConstraintsIsCA_constraint = Policy_Value.find(
                './constraint/constraint[@id=basicConstraintsIsCA]/value')
            basicConstraintsIsCA_constraint.text = isCA
            basicConstraintsPathLen_constraint = Policy_Value.find(
                './constraint/constraint[@id="basicConstraintsMaxPathLen"]/value')
            basicConstraintsPathLen_constraint.text = pathlength

    @classmethod
    def subject_key_identifier_extension_default(cls, root, policy_set_element):
        ''' This function defines Subject Key Identifier Extension Default Policy '''
        javaclass = 'subjectKeyIdentifierExtDefaultImpl'
        result = Common.check_policy(policy_set_element, javaclass)
        if not result:
            # Get Policy ID
            pvalue = Common.get_policy_id(policy_set_element)
            # Description
            Subject_Key_Identifier_Extension_Default_description = "This default populates a " + \
                "Subject Key Identifier Extension (2.5.29.14) to the request."
            # Policy Value
            Policy_Value = etree.SubElement(
                policy_set_element, 'value', id=pvalue)

            # Policy Definition
            Policy_definition = etree.SubElement(Policy_Value, 'def',
                                                 id='Subject Key Identifier Extension Default', classId='subjectKeyIdentifierExtDefaultImpl')
            Policy_description = etree.SubElement(Policy_definition,
                                                  'description').text = Subject_Key_Identifier_Extension_Default_description

            # Policy Attributes
            Subject_Key_Identifier_Extension_Default_attributes = [
                ('critical', 'string', 'readonly', 'Criticality', 'NULL'),
                ('keyid', 'string', 'readonly', 'Key ID', 'NULL')]
            cls.add_policy_attributes(
                Policy_definition, Subject_Key_Identifier_Extension_Default_attributes)
            # Policy parameters None
            # Constraint Definition
            Constraints.noConstraintImpl(Policy_Value)
        else:
            Policy_Value = Common.get_element_policy_value(
                policy_set_element, javaclass)

    @classmethod
    def signing_alg(cls, root, policy_set_element):
        ''' This Function defines Signing Algorithm Policy '''
        javaclass = 'signingAlgDefaultImpl'
        result = Common.check_policy(policy_set_element, javaclass)
        if not result:
            # get policy ID
            pvalue = Common.get_policy_id(policy_set_element)

            # Description
            Signing_Alg_description = "This default populates the Certificate Signing Algorithm." + \
                "The default values are Algorithm=SHA512withRSA"
            # Policy value
            Policy_Value = etree.SubElement(
                policy_set_element, 'value', id=pvalue)

            # Policy Definition
            Policy_definition = etree.SubElement(Policy_Value, 'def',
                                                 id='Signing Alg', classId='signingAlgDefaultImpl')
            Policy_description = etree.SubElement(Policy_definition,
                                                  'description').text = Signing_Alg_description

            # policy Attributes
            Signing_Alg_attributes = [('signingAlg', 'choice',
                                       'SHA1withRSA,SHA256withRSA,SHA512withRSA,SHA256withRSA/PSS,SHA384withRSA/PSS,'
                                       'SHA512withRSA/PSS',
                                       'Signing Algorithm', 'NULL')]
            cls.add_policy_attributes(
                Policy_definition, Signing_Alg_attributes)

            # Policy Parameters
            Signing_Alg_params = [('signingAlg', '-')]
            cls.add_policy_parameters(Policy_definition, Signing_Alg_params)

            # Constraint
            Constraints.signingAlgConstraintImpl(Policy_Value)
        else:
            Policy_Value = Common.get_element_policy_value(
                policy_set_element, javaclass)

    @classmethod
    def aia_extension_default(cls, root, policy_set_element):
        ''' This Function defines AIA Extension Default Policy '''
        javaclass = 'authInfoAccessExtDefaultImpl'
        result = Common.check_policy(policy_set_element, javaclass)
        if not result:
            # Get Policy ID
            pvalue = Common.get_policy_id(policy_set_element)
            s1 = 'This default populates a Authority Info Access Extension (1.3.6.1.5.5.7.1.1) to the request. '
            s2 = 'The default values are Criticality=false,Record #0{Method:1.3.6.1.5.5.7.48.1,Location Type:URIName,Location:,Enable:true}'
            AIA_Extension_description = s1 + s2

            # Policy Value
            Policy_Value = etree.SubElement(
                policy_set_element, 'value', id=pvalue)

            # Policy Definition
            Policy_definition = etree.SubElement(Policy_Value, 'def',
                                                 id='AIA Extension Default', classId='authInfoAccessExtDefaultImpl')
            Policy_description = etree.SubElement(
                Policy_definition, 'description').text = AIA_Extension_description

            # Policy Attributes
            AIA_Extension_Default_attributes = [
                ('authInfoAccessCritical', 'boolean',
                 'NULL', 'Criticality', 'false'),
                ('authInfoAccessGeneralNames', 'string_list', 'NULL', 'General Names', 'NULL')]
            cls.add_policy_attributes(
                Policy_definition, AIA_Extension_Default_attributes)

            # Policy Parameters
            AIA_Extension_Default_params = [
                ('authInfoAccessCritical', 'false'),
                ('authInfoAccessNumADs', '1'),
                ('authInfoAccessADMethod_0', '1.3.6.1.5.5.7.48.1'),
                ('authInfoAccessADLocationType_0', 'URIName'),
                ('authInfoAccessADLocation_0', ''),
                ('authInfoAccessADEnable_0', 'true')]

            cls.add_policy_parameters(
                Policy_definition, AIA_Extension_Default_params)
            # Constraint
            Constraints.noConstraintImpl(Policy_Value)
        else:
            Policy_Value = Common.get_element_policy_value(
                policy_set_element, javaclass)

    @classmethod
    def no_default(cls, root_element, policy_set_element, not_before, not_after):
        javaclass = 'noDefaultImpl'
        result = Common.check_policy(policy_set_element, javaclass)
        if not result:
            # Get Policy ID
            pvalue = Common.get_policy_id(policy_set_element)

            # Description
            No_Default_description = 'No Default'

            # Policy_Value
            Policy_Value = etree.SubElement(
                policy_set_element, 'value', id=pvalue)

            # Policy Definition
            Policy_definition = etree.SubElement(Policy_Value, 'def',
                                                 id='No Default', classId='noDefaultImpl')
            Policy_description = etree.SubElement(
                Policy_definition, 'description').text = No_Default_description

            # Policy Attributes None
            # Policy Parameters None
            # constraint
            Constraints.renewGracePeriodConstraintImpl(
                Policy_Value, not_before, not_after)
        else:
            Policy_Value = Common.get_element_policy_value(
                policy_set_element, javaclass)
            NotBeforeDefaultValue = Policy_Value.find(
                './constraint[@id="Renewal Grace Period Constraint"]/constraint[@id="renewal.graceBefore"]/descriptor/DefaultValue')
            NotBeforeDefaultValue.text = not_before
            NotBeforeValue = Policy_Value.find(
                './constraint[@id="Renewal Grace Period Constraint"]/constraint[@id="renewal.graceBefore"]/value')
            NotBeforeValue.text = not_before

            NotAfterDefaultValue = Policy_Value.find(
                './constraint[@id="Renewal Grace Period Constraint"]/constraint[@id="renewal.graceAfter"]/descriptor/DefaultValue')
            NotAfterDefaultValue.text = not_after
            NotAfterValue = Policy_Value.find(
                './constraint[@id="Renewal Grace Period Constraint"]/constraint[@id="renewal.graceAfter"]/value')
            NotAfterValue.text = not_after

    @classmethod
    def validity_default(cls, root, policy_set_element, default_range, range_value, range_unit):
        javaclass = 'validityDefaultImpl'
        result = Common.check_policy(policy_set_element, javaclass)

        if not result:
            # Get Policy ID
            pvalue = Common.get_policy_id(policy_set_element)

            # Description
            Validity_Default_description = "This default populates a Certificate" + \
                "Validity to the request. The default values are Range=180 in days"

            # policy value
            Policy_Value = etree.SubElement(
                policy_set_element, 'value', id=pvalue)

            # Policy Definition
            Policy_definition = etree.SubElement(Policy_Value, 'def',
                                                 id='Validity Default', classId='validityDefaultImpl')
            Policy_description = etree.SubElement(Policy_definition,
                                                  'description').text = Validity_Default_description
            # policy attributes
            Validity_Default_attributes = [
                ('notBefore', 'string', 'NULL', 'Not Before', 'NULL'),
                ('notAfter', 'string', 'NULL', 'Not After', 'NULL')]

            cls.add_policy_attributes(
                Policy_definition, Validity_Default_attributes)
            # Policy parameters

            Validity_Default_params = [
                ('range', default_range),
                ('rangeUnit', range_unit),
                ('startTime', '0')]

            cls.add_policy_parameters(
                Policy_definition, Validity_Default_params)

            # constraint
            Constraints.validityConstraintImpl(
                Policy_Value, default_range, range_value)
        else:
            Policy_Value = Common.get_element_policy_value(
                policy_set_element, javaclass)
            defaultRange_value = Policy_Value.find(
                './def/params[@name="range"]/value')
            defaultRange_value.text = default_range
            Constraint_DefaultValue = Policy_Value.find(
                './constraint[@id="Validity Constraint"]/constraint[@id="range"]/descriptor/DefaultValue')
            Constraint_DefaultValue.text = range_value
            Constraint_Value = Policy_Value.find(
                './constraint[@id="Validity Constraint"]/constraint[@id="range"]/value')
            Constraint_Value.text = range_value

    @classmethod
    def extended_key_usage_extension_default(cls, root, policy_set_element):
        javaclass = 'extendedKeyUsageExtDefaultImpl'
        result = Common.check_policy(policy_set_element, javaclass)
        if not result:
            # Get Policy ID
            pvalue = Common.get_policy_id(policy_set_element)
            # Description
            s1 = 'This default populates an Extended Key Usage Extension () to the request.'
            s2 = 'The default values are Criticality=false, OIDs=1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4'
            Extended_Key_Usage_Extension_Default_Description = s1 + s2
            # policy Value
            Policy_Value = etree.SubElement(
                policy_set_element, 'value', id=pvalue)
            # Policy Definition
            Policy_definition = etree.SubElement(Policy_Value, 'def',
                                                 id='Extended Key Usage Extension Default', classId='extendedKeyUsageExtDefaultImpl')
            Policy_description = etree.SubElement(Policy_definition,
                                                  'description').text = Extended_Key_Usage_Extension_Default_Description
            # Policy Attributes
            Extended_Key_Usage_Extension_Default_attributes = [
                ('exKeyUsageCritical', 'boolean', 'NULL', 'Criticality', 'false'),
                ('exKeyUsageOIDs', 'string_list', 'NULL', 'Comma-Separated list of Object Identifiers', 'false')]
            cls.add_policy_attributes(
                Policy_definition, Extended_Key_Usage_Extension_Default_attributes)

            # Policy Parameters
            Extended_Key_Usage_Extension_Default_params = [
                ('exKeyUsageCritical', 'false'),
                ('exKeyUsageOIDs', '1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4')]
            cls.add_policy_parameters(
                Policy_definition, Extended_Key_Usage_Extension_Default_params)
            # constraint
            Constraints.noConstraintImpl(Policy_Value)
        else:
            Policy_Value = Common.get_element_policy_value(
                policy_set_element, javaclass)

    @classmethod
    def subject_alt_name_constraint(cls, root, policy_set_element, alt_type, alt_pattern):

        javaclass = 'subjectAltNameExtDefaultImpl'
        result = Common.check_policy(policy_set_element, javaclass)
        if not result:
            # Get policy ID
            pvalue = Common.get_policy_id(policy_set_element)
            # Description
            s1 = 'This default populates a Subject Alternative Name Extension (2.5.29.17) to the request.'
            s2 = 'The default values are Criticality=false, Record #0{Pattern:$request.requestor_email$,Pattern Type:RFC822Name,Enable:true}'
            Subject_Alt_Name_Constraint_description = s1 + s2

            # Policy Value
            Policy_Value = etree.SubElement(
                policy_set_element, 'value', id=pvalue)
            # # Policy Definition
            Policy_definition = etree.SubElement(Policy_Value, 'def',
                                                 id='Subject Alt Name Constraint', classId='subjectAltNameExtDefaultImpl')
            Policy_description = etree.SubElement(
                Policy_definition, 'description').text = Subject_Alt_Name_Constraint_description

            # Policy Attributes
            Subject_Alt_Name_Constraint_attributes = [
                ('subjAltNameExtCritical', 'boolean',
                 'NULL', 'Criticality', 'false'),
                ('subjAltNames', 'string_list', 'NULL', 'General Names', 'NULL')]
            cls.add_policy_attributes(
                Policy_definition, Subject_Alt_Name_Constraint_attributes)

            # Policy Parameters
            Subject_Alt_Name_Constraint_params = [
                ('subjAltNameExtCritical', 'false'),
                ('subjAltNameNumGNs', '1'),
                ('subjAltExtType_0', alt_type),
                ('subjAltExtPattern_0', alt_pattern),
                ('subjAltExtGNEnable_0', 'true')]
            cls.add_policy_parameters(
                Policy_definition, Subject_Alt_Name_Constraint_params)
            # constraints
            Constraints.noConstraintImpl(Policy_Value)
        else:
            Policy_Value = Common.get_Element_PolicyValue(
                policy_set_element, javaclass)
            subjAltExtType_0_param = Policy_Value.find(
                './def/params[@name="subjAltExtType_0"]/value')
            subjAltExtType_0_param.text = alt_type
            subjAltExtPattern_0_param = Policy_Value.find(
                './def/params[@name="subjAltExtPattern_0"]/value')
            subjAltExtPattern_0_param.text = alt_pattern

    @classmethod
    def generic_extension(cls, root, policy_set_element):
        javaclass = 'genericExtDefaultImpl'
        result = Common.check_policy(policy_set_element, javaclass)
        if not result:
            # Get Policy ID
            pvalue = Common.get_policy_id(policy_set_element)

            # Description
            s1 = "This default populates a Generic Extension to the request." + \
                "The default values are Criticality=, OID=1.2.840.113549.1.9.15,"
            s2 = ' OID=1.2.840.113549.1.9.15, Value='
            s3 = "3067300B06092A864886F70D010105300B06092A864886F70D01010B300B06092A864886F70D" + \
                "01010C300B06092A864886F70D01010D300A06082A864886F70D0307300B060960864801650304010230" + \
                "0B060960864801650304012A300B06092A864886F70D010101"
            Generic_Extension_description = s1 + s2 + s3

            # Policy Value
            Policy_Value = etree.SubElement(
                policy_set_element, 'value', id=pvalue)

            # policy Definition
            Policy_definition = etree.SubElement(Policy_Value, 'def',
                                                 id='Generic Extension', classId='genericExtDefaultImpl')
            Policy_description = etree.SubElement(
                Policy_definition, 'description').text = Generic_Extension_description
            # Policy Attributes
            Generic_Extension_attributes = [
                ('genericExtCritical', 'boolean', 'NULL', 'Criticality', 'false'),
                ('genericExtData', 'string_list', 'NULL', 'Extension Value', 'NULL')]
            # Policy parameters
            Generic_Extension_params = [
                ('genericExtCritical', ''),
                ('genericExtOID', '1.2.840.113549.1.9.15'),
                ('genericExtData', s3)]
            cls.add_policy_parameters(
                Policy_definition, Generic_Extension_params)

            # Constraints
            Constraints.noConstraintImpl(Policy_Value)
            # Constraints.subjectNameConstraintImpl(Policy_Value,subject_pattern)
        else:
            Policy_Value = Common.get_element_policy_value(
                policy_set_element, javaclass)

    @classmethod
    def netscape_certificate_type_extension_default(cls, root, policy_set_element, extlist):
        javaclass = 'nsCertTypeExtDefaultImpl'
        result = Common.check_policy(policy_set_element, javaclass)
        if not result:
            # Get policy ID
            pvalue = Common.get_policy_id(policy_set_element)
            # Description
            Netscape_Certificate_Type_description = 'This default populates a Netscape Certificate Type Extension'

            # Policy Value
            Policy_Value = etree.SubElement(
                policy_set_element, 'value', id=pvalue)

            # policy definition
            Policy_definition = etree.SubElement(Policy_Value, 'def',
                                                 id='Netscape Certificate Type Extension Default', classId='nsCertTypeExtDefaultImpl')
            Policy_description = etree.SubElement(Policy_definition,
                                                  'description').text = Netscape_Certificate_Type_description
            # Policy Attributes
            Netscape_Certificate_Type_Extension_Default_attributes = [
                ('nsCertCritical', 'boolean', 'NULL', 'Criticality', 'false'),
                ('nsCertSSLClient', 'boolean', 'NULL', 'SSL Client', 'false'),
                ('nsCertSSLServer', 'boolean', 'NULL', 'SSL Server', 'false'),
                ('nsCertEmail', 'boolean', 'NULL', 'Email', 'false'),
                ('nsCertObjectSigning', 'boolean',
                 'NULL', 'Object Signing', 'false'),
                ('nsCertSSLCA', 'boolean', 'NULL', 'SSL CA', 'false'),
                ('nsCertEmailCA', 'boolean', 'NULL', 'Email CA', 'false'),
                ('nsCertObjectSigningCA', 'boolean', 'NULL', 'Object Signing CA', 'false')]

            cls.add_policy_attributes(Policy_definition, Netscape_Certificate_Type_Extension_Default_attributes)

            # Policy parameters
            Netscape_Certificate_Type_Extension_Default_params = [
                ('nsCertCritical', Common.check_ext_key_usage(
                    extlist, 'nsCertCritical')),
                ('nsCertSSLClient', Common.check_ext_key_usage(
                    extlist, 'nsCertSSLClient')),
                ('nsCertEmail', Common.check_ext_key_usage(extlist, 'nsCertEmail')),
                ('nsCertObjectSigning', Common.check_ext_key_usage(
                    extlist, 'nsCertObjectSigning')),
                ('nsCertSSLCA', Common.check_ext_key_usage(extlist, 'nsCertSSLCA')),
                ('nsCertEmailCA', Common.check_ext_key_usage(
                    extlist, 'nsCertEmailCA')),
                ('nsCertObjectSigningCA', Common.check_ext_key_usage(extlist, 'nsCertObjectSigningCA'))]
            cls.add_policy_parameters(
                Policy_definition, Netscape_Certificate_Type_Extension_Default_params)

            # Constraints
            Constraints.noConstraintImpl(Policy_Value)
        else:
            Policy_Value = Common.get_element_policy_value(
                policy_set_element, javaclass)
            for v in extlist:
                result = Policy_Value.find("./def/params[@name=\"%s\"]" % v)
                result[0].text = 'true'

    @classmethod
    def crl_distribution_points_ext_default(cls, root, policy_set_element, crlurl):
        javaclass = 'crlDistributionPointsExtDefaultImpl'
        result = Common.check_policy(policy_set_element, javaclass)

        if not result:

            # Get Policy ID
            pvalue = Common.get_policy_id(policy_set_element)

            # Description
            s1 = 'This default populates a CRL Distribution Points Extension (2.5.29.31) to the request'
            s2 = 'The default values are Criticality=false, Record #0{Point Type:URIName,Point Name:http://localhost.localdomain:9180/ca/ee/ca/getCRL'
            s3 = '?crlIssuingPoint=MasterCRL&amp;op=getCRL&amp;crlDisplayType=cachedCRL&amp;submit=Submit,Reasons:,Issuer Type'
            s4 = ':,Issuer Name:,Enable:true}'

            clrDistribution_Point_Name = 'http://localhost.localdomain:9180/ca/ee/ca/getCRL?crlIssuingPoint=MasterCRL&amp;op=getCRL&amp;crlDisplayType=cachedCRL&amp;submit=Submit'
            # Policy Value
            Policy_Value = etree.SubElement(
                policy_set_element, 'value', id=pvalue)
            Policy_definition = etree.SubElement(Policy_Value, 'def',
                                                 id='crlDistributionPointsExtDefaultImpl', classId='crlDistributionPointsExtDefaultImpl')
            Policy_description = etree.SubElement(
                Policy_definition, 'description').text = s1 + s2 + s3 + s4

            # Policy Attributes
            crl_Distribution_Points_Ext_Default_attributes = [
                ('crlDistPointsCritical', 'boolean',
                 'NULL', 'Criticality', 'false'),
                ('crlDistPointsValue', 'string_list', 'NULL', 'CRL Distribution Points', 'NULL')]
            # params
            crl_Distribution_Points_Ext_Default_params = [
                ('crlDistPointsNum', '1'),
                ('crlDistPointsPointType_0', 'URIName'),
                ('crlDistPointsPointName_0', crlurl),
                ('crlDistPointsReasons_0', 'NULL'),
                ('crlDistPointsIssuerType_0', 'NULL'),
                ('crlDistPointsIssuerName_0', 'NULL'),
                ('crlDistPointsEnable_0', 'true')]
            cls.add_policy_parameters(
                Policy_definition, crl_Distribution_Points_Ext_Default_params)

            # no constraint
            Constraints.noConstraintImpl(Policy_Value)
        else:
            Policy_Value = Common.get_element_policy_value(
                policy_set_element, javaclass)
            crlDistPointsPointName_value = Policy_Value.find(
                './def/params[@name="crlDistPointsPointName_0"]/value')
            crlDistPointsPointName_value[0].text = crlurl

    @classmethod
    def user_supplied_extension_default(cls, root, policy_set_element, ExtOID, extra_args):
        javaclass = 'userExtensionDefaultImpl'
        result = Common.check_policy(policy_set_element, javaclass)
        if not result:
            # Get policy ID
            pvalue = Common.get_policy_id(policy_set_element)

            # Description
            s1 = 'This default populates a User-Supplied Extension (%s) to the request.' % (
                ExtOID)

            # policy value
            Policy_Value = etree.SubElement(
                policy_set_element, 'value', id=pvalue)

            # policy defintion
            Policy_definition = etree.SubElement(Policy_Value, 'def')
            Policy_definition.attrib['id'] = 'User Supplied Key Usage Extension'
            Policy_definition.attrib['classId'] = 'userExtensionDefaultImpl'
            Policy_description = etree.SubElement(
                Policy_definition, 'description').text = s1

            # policy Attributes
            User_Supplied_Extension_Default_attributes = [
                ('userExtOID', 'string', 'readonly', 'Object Identifier', 'NULL')]

            # policy params
            User_Supplied_Extension_Default_params = [('userExtOID', ExtOID)]
            cls.add_policy_parameters(
                Policy_definition, User_Supplied_Extension_Default_params)

            # No constraint
            if ExtOID in '2.5.29.17':
                Constraints.subjectNameConstraintImpl(Policy_Value, extra_args)
            else:
                Constraints.noConstraintImpl(Policy_Value)
        else:
            Policy_Value = Common.get_element_policy_value(
                policy_set_element, javaclass)
            userExtOID_param = Policy_Value.find(
                './def/params[@name="userExtOID"]/value')
            userExtOID_param.text = ExtOID

class Setup(object):
    '''Create/Modify Profile xml'''

    def __init__(self, profile_type, profile_id, profile_xml=None):
        self.profile_type = profile_type
        self.profile_id = profile_id
        self.profile_xml = profile_xml
        self.output = []
        self.profile_data = {}

    def generate_profile_parameters(self, user_params=None):
        '''
        Generate parameters(policies, validity,extensions) required for profile

        :param dict user_params: Dictionary containing user specified parameters
            for certain policies

        :Returns dict profile_input: containing Parameters/features that will be
            set to a profile
        '''
        profile_input = {}
        profile_input['ProfileId'] = self.profile_id
        if self.profile_type in ('user', 'smime'):
            profile_name = 'Manual User Dual-Use Certificate Enrollment'
            profile_description = 'This certificate profile is for enrolling user certificates'
            profile_input['Key_Generation_Class'] = 'keyGenInputImpl'
            profile_input['Key_Generate_InputId'] = '1'
            profile_input['subject_Name_Input_Id'] = '2'
            profile_input['Submitter_Info_InputId'] = '3'
            key_list = ('keyUsageCritical', 'keyUsageDigitalSignature', 'keyUsageNonRepudiation',
                        'keyUsageKeyEncipherment')
            subject_pattern = 'UID=.*'
            policy_set_name = 'pkitest1'
        elif self.profile_type in ('server', 'other'):
            profile_name = "Manual Server Certificate Enrollment"
            profile_description = "This certificate profile is for enrolling dual user certificates"
            profile_input['Key_Generation_Class'] = 'certReqInputImpl'
            profile_input['Key_Generate_InputId'] = '1'
            profile_input['Submitter_Info_InputId'] = '2'
            key_list = ('keyUsageCritical', 'keyUsageDigitalSignature', 'keyUsageNonRepudiation',
                        'keyUsageKeyEncipherment')
            subject_pattern = 'CN=.*'
            policy_set_name = 'pkitest1'
        elif self.profile_type is 'dualcert':
            profile_name = "Manual User Signing and Encryption Certificates Enrollment"
            profile_description = "This certificate profile is for enrolling dual user certificates"
            profile_input['Key_Generation_Class'] = 'dualKeyGenInputImpl'
            profile_input['Key_Generate_InputId'] = '1'
            profile_input['subject_Name_Input_Id'] = '2'
            profile_input['Submitter_Info_InputId'] = '3'
            key_list = ('keyUsageCritical', 'keyUsageKeyEncipherment')
            subject_pattern = 'UID=.*'
            policy_set_name = 'encryptionCertSet'
        elif self.profile_type is 'ca':
            policy_set_name = 'caCertSet'
            profile_name = "Manual Certificate Manager Signing Certificate Enrollment"
            profile_description = "This certificate profile is for enrolling Certificate Authority certificates."
            profile_input['Key_Generation_Class'] = 'certReqInputImpl'
            profile_input['Key_Generate_InputId'] = '1'
            profile_input['Submitter_Info_InputId'] = '2'
            key_list = ('keyUsageCritical', 'keyUsageDigitalSignature', 'keyUsageNonRepudiation',
                        'keyUsagekeyCertSign', 'keyUsageCrlSign')
            subject_pattern = 'CN=.*'
            profile_input['isCA'] = "true"
            try:
                user_params['PathLength'] = user_params['PathLength']
            except (KeyError, TypeError):
                profile_input['PathLength'] = "-1"
        # policySets
        profile_input['PolicySet'] = policy_set_name

        # subjectNamePattern
        try:
            profile_input['Subject_Pattern'] = user_params[
                'subjectNamePattern']
        except (KeyError, TypeError) as E:
            profile_input['Subject_Pattern'] = subject_pattern

        # SubjectNameDefault
        try:
            profile_input['subjectNameDefault'] = user_params[
                'subjectNameDefault']
        except (KeyError, TypeError) as E:
            profile_input['subjectNameDefault'] = None

        # profileName
        try:
            profile_input['name'] = user_params['ProfileName']
        except (KeyError, TypeError) as E:
            profile_input['name'] = profile_name

        # profiledescription
        try:
            profile_input['Description'] = user_params['Description']
        except (KeyError, TypeError):
            profile_input['Description'] = profile_description

        # profilekeyusageextensions
        try:
            profile_input['Key_List'] = user_params['KeyUsageExtensions']
        except (KeyError, TypeError):
            profile_input['Key_List'] = key_list
        # NotBefore
        try:
            profile_input['NotBefore'] = user_params['notBefore']
        except (KeyError, TypeError):
            profile_input['NotBefore'] = '30'
        # NotAfter
        try:
            profile_input['NotAfter'] = user_params['notAfter']
        except (KeyError, TypeError):
            profile_input['NotAfter'] = '30'
        # validity
        try:
            profile_input['Validity'] = user_params['ValidFor']
        except (KeyError, TypeError):
            profile_input['Validity'] = '180'
        #rangeunit
        try:
            profile_input['rangeunit'] = user_params['rangeunit']
        except (KeyError, TypeError):
            profile_input['rangeunit'] = 'minute'
        # max validity
        try:
            profile_input['MaxValidity'] = user_params['MaxValidity']
        except (KeyError, TypeError):
            profile_input['MaxValidity'] = '365'
        # netscapeextensions
        try:
            profile_input['NetscapeExtensions'] = user_params[
                'NetscapeExtensions']
        except (KeyError, TypeError):
            pass
        # if smime, add generic extensions
        if self.profile_type is 'smime':
            profile_input['Generic_extensions'] = 'true'

        # include crl extensions
        try:
            profile_input['crlurl'] = user_params['CrlExtensions']
        except (KeyError, TypeError):
            pass

        # any other alternate pattern
        try:
            profile_input['altPattern'] = user_params['altPattern']
        except (KeyError, TypeError):
            profile_input['altPattern'] = "$request.requestor_email$"

        # Alt type RFC822Name
        try:
            profile_input['altType'] = user_params['altType']
        except (KeyError, TypeError):
            profile_input['altType'] = 'RFC822Name'
        # ExtOID
        try:
            profile_input['ExtOID'] = user_params['ExtOID']
        except (KeyError, TypeError):
            pass
        self.profile_data = profile_input
        return profile_input

    def add_description(self, profile_id, profile_name, profile_description):
        '''
        Creates first part of the profile xml which contains
            name, description, whether profile is enabled, disabled

        :params str profileid: Id of the profile('caUsercert')
        :params str profilename: Name of the profile
        :params str profiledescription: Description of the profile

        :Returns etree.Element root: root element of the xml
        '''
        # our profile starts with Profile Tag
        root = etree.Element("Profile", id=profile_id)
        # In future the this could be a arguement to be passed
        classId = etree.SubElement(root, "classId").text = 'caEnrollImpl'
        # Profile Name
        name = etree.SubElement(root, "name").text = profile_name
        # Profile Description
        description = etree.SubElement(
            root, "description").text = profile_description

        enabled = etree.SubElement(root, "enabled").text = 'false'
        visible = etree.SubElement(root, "visible").text = 'true'
        enabledBy = etree.SubElement(root, "enabledBy")
        authzAcl = etree.SubElement(root, "authzAcl")
        renew = etree.SubElement(root, "renewal").text = 'false'
        xmlOutput = etree.SubElement(root, "xmlOutput").text = 'false'

        return root

    # oldmethod: def key_gen(root,InputClassID,InputId):
    def add_key_gen(self, root, input_class_id, input_id):
        '''
        Add Key generation to profile
        :params etree.Elementree root: root element of xml
        :params str input_class_id: certReqInputImpl/keyGenInputImpl/dualKeyGenInputImpl
        :params str input_id:
        '''
        Input = etree.SubElement(root, "Input", id='i' + input_id)
        classId = etree.SubElement(Input, 'ClassID').text = input_class_id
        name = etree.SubElement(Input, 'Name').text = 'Key Generation'

        if input_class_id == 'dualKeyGenInputImpl':
            input_attributes = [
                ('cert_request_type', 'dual_keygen_request_type',
                 'Key Generation Request Type'),
                ('cert_request', 'dual_keygen_request', 'Key Generation Request')]
        elif input_class_id == 'keyGenInputImpl':
            input_attributes = [
                ('cert_request_type', 'keygen_request_type',
                 'Key Generation Request Type'),
                ('cert_request', 'keygen_request', 'Key Generation Request')]
        elif input_class_id == 'certReqInputImpl':
            input_attributes = [
                ('cert_request_type', 'cert_request_type',
                 'Certificate Request Type'),
                ('cert_request', 'cert_request', 'Certificate Request')]
        else:
            print('%s did not match with valid Input ClassId' %
                  (input_class_id))
            # todo raise an exception, in oldmethod i used sys.exit
            return False

        for idx, (name, syntax, description) in enumerate(input_attributes):
            Attribute = etree.SubElement(Input, 'Attribute', name=name)
            Descriptor = etree.SubElement(Attribute, 'Descriptor')
            syntax = etree.SubElement(Descriptor, 'Syntax').text = syntax
            Description = etree.SubElement(
                Descriptor, 'Description').text = description

        return True

    def add_subject_name_input(self, root, input_id):
        '''
        Add Subject Name input values to profile xml
            example: uid,email,cn,ou3,ou2,ou1,ou,c
        :params etree.ElementTree root: root element of xml
        :params str input_id:

        :Returns None
        '''
        subject_name_values = [
            ('sn_uid', 'UID'),
            ('sn_e', 'Email'),
            ('sn_cn', 'Common Name'),
            ('sn_ou3', 'Organizational Unit 3'),
            ('sn_ou2', 'Organizational Unit 2'),
            ('sn_ou1', 'Organizational Unit 1'),
            ('sn_ou', 'Organizational Unit'),
            ('sn_o', 'Organization'),
            ('sn_c', 'Country')]

        Input = etree.SubElement(root, "Input", id='i' + input_id)
        classId = etree.SubElement(
            Input, 'ClassID').text = 'subjectNameInputImpl'
        name = etree.SubElement(Input, 'Name').text = 'Subject Name'

        for idx, (attr_name, desc_value) in enumerate(subject_name_values):
            Attribute = etree.SubElement(Input, 'Attribute', name=attr_name)
            Descriptor = etree.SubElement(Attribute, 'Descriptor')
            syntax = etree.SubElement(Descriptor, 'Syntax').text = 'string'
            description = etree.SubElement(
                Descriptor, 'Description').text = desc_value

    def add_submitter_info(self, root, input_id):
        '''
        Add Submitter info to the xml like 'Requestor Name, email, phone'
        :params etree.ElementTree root: root element of the xml
        :input_id:
        '''
        Input = etree.SubElement(root, "Input", id='i' + input_id)
        classId = etree.SubElement(
            Input, 'ClassID').text = 'submitterInfoInputImpl'
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
            description = etree.SubElement(
                Descriptor, 'Description').text = desc_value

    def add_output_info(self, root):
        '''
        Add Ouput information to xml like Certificate Output, java class used
        :params etree.ElementTree root: root element of the xml

        :Returns None
        '''
        output = etree.SubElement(root, "Output", id="o1")
        Name = etree.SubElement(output, 'name').text = 'Certificate Output'
        output_classId = etree.SubElement(
            output, 'classId').text = 'certOutputImpl'

        output_attributes = [
            ('pretty_cert', 'pretty_print', 'Certificate Pretty Print'),
            ('b64_cert', 'pretty_print', 'Certificate Base-64 Encoded')]

        for idx, (name, syntax, description) in enumerate(output_attributes):
            Attribute = etree.SubElement(output, 'attributes', name=name)
            Descriptor = etree.SubElement(Attribute, 'Descriptor')
            Syntax = etree.SubElement(Descriptor, 'Syntax').text = syntax
            Description = etree.SubElement(
                Descriptor, 'Description').text = description

    def add_policysets_element(self, root):
        '''
        Create PolicySets subElement under Profile, where
        all policies for certificate will be defined
        :params etree.ElementTree root: root element of the xml

        :Returns etree.ElementTree: root, PolicSets
        '''
        policy_sets_element = etree.SubElement(root, "PolicySets")
        return policy_sets_element

    def add_policy_set_element(self, root_element, policy_sets_element, policy_set_name):
        '''
        Create PolicySet Element under PolicySets in the profile xml
        '''
        #PolicySets = root_element.find('./PolicySets')
        policy_set_element = etree.SubElement(policy_sets_element, 'PolicySet')
        policySetId = etree.SubElement(
            policy_set_element, 'id').text = policy_set_name
        return policy_set_element

    def add_policies(self, root_element, policy_set_element, profile_input):
        ''' Add Policies to profiles '''
        if profile_input['subjectNameDefault'] is None:
            Policy.subject_name_default(root_element, policy_set_element,
                                        profile_input['Subject_Pattern'], None)
        else:
            Policy.subject_name_default(root_element, policy_set_element,
                                        profile_input['Subject_Pattern'],
                                        profile_input['subjectNameDefault'])

        if not (('PathLength' in profile_input) and  ('isCA' in profile_input)):
            Policy.no_default(root_element,
                              policy_set_element,
                              profile_input['NotBefore'],
                              profile_input['NotAfter'])
            Policy.validity_default(root_element, policy_set_element,
                                    profile_input['Validity'],
                                    profile_input['MaxValidity'],
                                    profile_input['rangeunit'])
            Policy.extended_key_usage_extension_default(
                root_element, policy_set_element)

            if 'ExtOID' in profile_input:
                if profile_input['ExtOID'] in '2.5.29.17':
                    Policy.user_supplied_extension_default(root_element, policy_set_element,
                                                           profile_input['ExtOID'], profile_input['Subject_Pattern'])
                else:
                    Policy.user_supplied_extension_default(root_element, policy_set_element,
                                                           profile_input['ExtOID'], None)
            Policy.subject_alt_name_constraint(root_element, policy_set_element,
                                               profile_input['altType'],
                                               profile_input['altPattern'])
        Policy.key_default(root_element, policy_set_element)
        Policy.authority_key_identifier_default(
            root_element, policy_set_element)
        Policy.aia_extension_default(root_element, policy_set_element)
        Policy.key_usage_default(
            root_element, policy_set_element, profile_input['Key_List'])
        Policy.signing_alg(root_element, policy_set_element)
        if 'Generic_extensions' in profile_input:
            Policy.generic_extension(root_element, policy_set_element)
        if 'NetscapeExtensions' in profile_input:
            Policy.netscape_certificate_type_extension_default(root_element, policy_set_element,
                                                               profile_input['NetscapeExtensions'])
        if 'crlurl' in profile_input:
            Policy.crl_distribution_points_ext_default(root_element, policy_set_element,
                                                       profile_input['crlurl'])
        if 'PathLength' in profile_input and 'isCA' in profile_input:
            Policy.basic_constraints_extension_default(root_element, policy_set_element,
                                                       profile_input['PathLength'], profile_input['isCA'])
            Policy.ca_certificate_validity_default(
                root_element, policy_set_element)
            Policy.subject_key_identifier_extension_default(
                root_element, policy_set_element)
        et = etree.ElementTree(root_element)
        return et

    def create_profile(self, user_params=None):
        '''
        Create a custom profile based on user provided parameters

        :params dict user_params: Dictionary containing user provided
            values to policies, extensions
        '''
        profile_input = self.generate_profile_parameters(user_params)
        # Create initial profile name, description
        root_element = self.add_description(
            profile_input['ProfileId'],
            profile_input['name'],
            profile_input['Description']
        )
        # Add Key Generation input class to the xml
        ret = self.add_key_gen(root_element,
                               profile_input['Key_Generation_Class'],
                               profile_input['Key_Generate_InputId'])

        # Add subject name input and submitter information
        if 'subject_Name_Input_Id' in profile_input:
            self.add_subject_name_input(root_element, profile_input[
                                        'subject_Name_Input_Id'])
            self.add_submitter_info(root_element, profile_input[
                                    'Submitter_Info_InputId'])
        else:
            self.add_submitter_info(root_element, profile_input[
                                    'Submitter_Info_InputId'])

        # Add certificate output information
        self.add_output_info(root_element)

        # Add PolicySets Element
        policy_sets_element = self.add_policysets_element(root_element)

        # Add PolicySet Element under PolicySets Element
        policy_set_element = self.add_policy_set_element(root_element, policy_sets_element,
                                                         profile_input['PolicySet'])
        et = self.add_policies(root_element, policy_set_element, profile_input)
        output1_fd, output1_path = tempfile.mkstemp(
            suffix='cfg.xml', prefix='profile')
        et.write(output1_path, pretty_print=True)
        self.output.append(output1_path)
        os.close(output1_fd)
        if self.profile_type is 'dualcert':
            keylist2 = ('keyUsageCritical',
                        'keyUsageDigitalSignature',
                        'keyUsageNonRepudiation')
            subjectPattern = profile_input['Subject_Pattern']
            subjectDefault = profile_input['subjectNameDefault']
            notBefore = profile_input['NotBefore']
            notAfter = profile_input['NotAfter']
            validfor = profile_input['Validity']
            rangeunit = profile_input['rangeunit']
            maxvalidity = profile_input['MaxValidity']
            altType = profile_input['altType']
            altPattern = profile_input['altPattern']

            profile_input2 = {
                'PolicySet': 'signingCertSet',
                'Subject_Pattern': subjectPattern,
                'subjectNameDefault': subjectDefault,
                'Key_List': keylist2,
                'NotBefore': notBefore,
                'NotAfter': notAfter,
                'Validity': validfor,
                'rangeunit': rangeunit,
                'MaxValidity': maxvalidity,
                'altType': altType,
                'altPattern': altPattern}

            policy_set_element = self.add_policy_set_element(root_element,
                                                             policy_sets_element, profile_input2['PolicySet'])
            et = self.add_policies(
                root_element, policy_set_element, profile_input2)
            output2_fd, output2_path = tempfile.mkstemp(
                suffix='cfg.xml', prefix='profile')
            et.write(output2_path, pretty_print=True)
            self.output.append(output2_path)
            os.close(output2_fd)
            return self.output
        else:
            return self.output

    def edit_profile(self, user_params):
        ''' Edit Profile '''
        parser = etree.XMLParser(remove_blank_text=True)
        root_element = etree.parse(self.profile_xml, parser)
        policy_set_element = root_element.find('./PolicySets/PolicySet')

        if 'ProfileName' in user_params:
            profile_name = root_element.find('name')
            profile_name.text = user_params['name']

        if 'Description' in user_params:
            profile_description = root_element.find('description')
            profile_description = user_params['Description']

        if 'subjectNamePattern' in user_params and not('subjectNameDefault' in user_params):
            Profile.subject_name_default(
                root_element,
                policy_set_element,
                user_params['subjectNamePattern'],
                None)
        elif not('subjectNamePattern' in user_params) and 'subjectNameDefault' in user_params:
            Profile.subject_name_default(
                root_element,
                policy_set_element,
                None,
                user_params['subjectNameDefault'])
        else:
            Profile.subject_name_default(
                root_element,
                policy_set_element,
                user_params['subjectNamePattern'],
                user_params['subjectNameDefault'])

        if 'KeyUsageExtensions' in user_params:
            Policy.key_usage_default(
                root_element,
                policy_set_element,
                user_params['Key_List'])


        if 'MaxValidity' in user_params and 'ValidFor' in user_params and 'rangeunit' in user_params:
            Policy.validity_default(
                root_element,
                policy_set_element,
                user_params['Validity'],
                user_params['MaxValidity'],
                user_params['rangeunit'])

        if 'NotBefore' in user_params and 'NotAfter' in user_params:
            Policy.no_default(
                root_element,
                policy_set_element,
                user_params['NotBefore'],
                user_params['NotAfter'])

        if 'NetscapeExtensions' in user_params:
            Policy.netscape_certificate_type_extension_default(
                root_element,
                policy_set_element,
                user_params['NetscapeExtensions'])

        if 'CrlExtensions' in user_params:
            Policy.crl_distribution_points_ext_default(
                root_element,
                policy_set_element,
                user_params['CrlExtensions'])

        if 'PathLength' in user_params and 'isCA' in user_params:
            Policy.basic_constraints_extension_default(
                root_element,
                policy_set_element,
                user_params['PathLength'],
                user_params['isCA'])
            Policy.ca_certificate_validity_default(
                root_element, policy_set_element)
            Policy.subject_key_identifier_extension_default(
                root_element, policy_set_element)
        et = etree.ElementTree(root_element)

        return et
