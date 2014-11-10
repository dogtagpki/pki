#!/usr/bin/python
# -*- coding: utf-8 -*
from lxml import etree
#import pkicommonlib as common
import PkiLib.pkicommonlib as common

def validityConstraintImpl(Policy_Value,default_value,range_value):


    constraint_definition = etree.SubElement(Policy_Value, 'constraint', id='Validity Constraint')
    s1 = 'This constraint rejects the validity that is not between %s days.' % (range_value)
    constraint_description = etree.SubElement(constraint_definition, 'description').text = s1
    constraint_classid = etree.SubElement(constraint_definition, 'classId').text = 'validityConstraintImpl'

    validityConstraintImpl_attributes = [
            ('range', 'integer', 'NULL', 'Validity Range (in days)', str(default_value), str(range_value)),
            ('notBeforeGracePeriod', 'integer', 'NULL','Grace period for Not Before being set in the future (in seconds).', '0', 'NULL'),
            ('notBeforeCheck', 'boolean', 'NULL','Check Not Before against current time', 'false', 'false'),
            ('notAfterCheck','boolean', 'NULL', 'Check Not After against Not Before', 'false', 'false')]

    common.constraint_attributes(constraint_definition, validityConstraintImpl_attributes)

def subjectNameConstraintImpl(Policy_Value,subjectPattern):

    constraint_definition = etree.SubElement(Policy_Value, 'constraint', id='Subject Name Constraint')
    constraint_description = etree.SubElement(constraint_definition, 'description').text = 'This constraint accepts the subject name that matches ' + subjectPattern
    constraint_classid = etree.SubElement(constraint_definition, 'classId').text = 'subjectNameConstraintImpl'

    subjectNameConstraintImpl_attributes = [('pattern','string','NULL','Subject Name Pattern','NULL',subjectPattern)]

    common.constraint_attributes(constraint_definition, subjectNameConstraintImpl_attributes)


def noConstraintImpl(Policy_Value):
    constraint_definition = etree.SubElement(Policy_Value, 'constraint', id='No Constraint')
    constraint_description = etree.SubElement(constraint_definition, 'description').text = 'No Constraint'
    constraint_classid = etree.SubElement(constraint_definition, 'classId').text = 'noConstraintImpl'

def basicConstraintsCritical(Policy_Value,PathLength,isCA):

    constraint_definition = etree.SubElement(Policy_Value, 'constraint', id='Basic Constraint Extension Constraint')
    s1 = 'This constraint accepts the Basic Constraint extension, if present, only when Criticality=true,'
    s2 = 'Is CA=true, Min Path Length=-1, Max Path Length=-1'
    constraint_description = etree.SubElement(constraint_definition, 'description').text = s1 + s2
    constraint_classid = etree.SubElement(constraint_definition, 'classId').text = 'basicConstraintsExtConstraintImpl'

    basicConstraintsCritical_attributes = [
            ('basicConstraintsCritical','choice', 'true,false,-', 'Criticality', '-', 'true'),
            ('basicConstraintsIsCA', 'choice', 'true,false,-', 'Is CA', '-', isCA),
            ('basicConstraintsMinPathLen', 'integer','NULL', 'Min Path Length','-1', PathLength),
            ('basicConstraintsMaxPathLen', 'integer', 'NULL','Max Path Length', '100', '100')
            ]
    common.constraint_attributes(constraint_definition, basicConstraintsCritical_attributes)

def signingAlgConstraintImpl(Policy_Value):

    constraint_definition = etree.SubElement(Policy_Value, 'constraint', id='No Constraint')
    s1 = 'This constraint accepts only the Signing Algorithms of SHA1withRSA,SHA256withRSA,SHA512withRSA,'
    s2 = 'MD5withRSA,MD2withRSA,SHA1withDSA,SHA1withEC,SHA256withEC,SHA384withEC,SHA512withEC'
    constraint_description = etree.SubElement(constraint_definition, 'description').text = s1 + s2
    constraint_classid = etree.SubElement(constraint_definition, 'classId').text = 'signingAlgConstraintImpl'

    signingAlgConstraintImpl_attributes = [
            ('signingAlgsAllowed', 'string','NULL','Allowed Signing Algorithms',
                'SHA1withRSA,MD5withRSA,MD2withRSA,SHA1withDSA,SHA256withRSA,SHA512withRSA,SHA1withEC,SHA256withEC,SHA384withEC,SHA512withEC',
                'SHA1withRSA,SHA256withRSA,SHA512withRSA,MD5withRSA,MD2withRSA,SHA1withEC,SHA256withEC,SHA384withEC,SHA512withEC')]

    common.constraint_attributes(constraint_definition, signingAlgConstraintImpl_attributes)

def renewGracePeriodConstraintImpl(Policy_Value,notBefore,notAfter):
    
    constraint_definition = etree.SubElement(Policy_Value, 'constraint', id='Renewal Grace Period Constraint')
    s1 = 'This constraint rejects the validity that is not between %s days before' %(notBefore)
    s2 = 'and %s days after original cert expiration date days.' %(notAfter)
    constraint_description = etree.SubElement(constraint_definition, 'description').text = s1 + s2
    constraint_classid = etree.SubElement(constraint_definition, 'classId').text = 'renewGracePeriodConstraintImpl'

    renewGracePeriodConstraintImpl_attributes = [
            ('renewal.graceBefore', 'integer', 'NULL', 'Renewal Grace Period Before', notBefore, notBefore),
            ('renewal.graceAfter', 'integer', 'NULL', 'Renewal Grace Period After', notAfter, notAfter)]

    common.constraint_attributes(constraint_definition, renewGracePeriodConstraintImpl_attributes)

def keyUsageExtConstraintImpl(Policy_Value,keylist):
    constraint_definition = etree.SubElement(Policy_Value, 'constraint', id='Key Usage Extension Constraint')

    def1 = 'This constraint accepts the Key Usage extension, if present, only when Criticality=true, Digital Signature=true,'
    def2 = 'Non-Repudiation=true, Key Encipherment=true, Data Encipherment=false,'
    def3 = 'Key Agreement=false, Key Certificate Sign=false, Key CRL Sign=false, Encipher Only=false, Decipher Only=false'

    constraint_description = etree.SubElement(constraint_definition, 'description').text = def1 + def2 + def3
    constraint_classid = etree.SubElement(constraint_definition, 'classId').text = 'keyUsageExtConstraintImpl'
    
    key_default_list = (
            'keyUsageCritical','keyUsageDigitalSignature', 'keyUsageNonRepudiation', 
            'keyUsageKeyEncipherment', 'keyUsageDataEncipherment', 'keyUsageKeyAgreement', 
            'keyUsageKeyCertSign', 'keyUsageCrlSign','keyUsageEncipherOnly',
            'keyUsageDecipherOnly')

    keyUsageExtConstraintImpl_attributes = [
            (key_default_list[0], 'choice', 'true,false,-', 'Criticality', '-', common.check_ext_key_usage(keylist,key_default_list[0])),
            (key_default_list[1], 'choice', 'true,false,-', 'Digital Signature', '-', common.check_ext_key_usage(keylist,key_default_list[1])),
            (key_default_list[2], 'choice', 'true,false,-', 'Non-Repudiation', '-',  common.check_ext_key_usage(keylist,key_default_list[2])),
            (key_default_list[3], 'choice', 'true,false,-', 'Key Encipherment', '-', common.check_ext_key_usage(keylist,key_default_list[3])),
            (key_default_list[4], 'choice', 'true,false,-', 'Data Encipherment', '-', common.check_ext_key_usage(keylist,key_default_list[4])),
            (key_default_list[5], 'choice', 'true,false,-', 'Key Agreement', '-', common.check_ext_key_usage(keylist,key_default_list[5])),
            (key_default_list[6], 'choice', 'true,false,-', 'Key CertSign', '-', common.check_ext_key_usage(keylist,key_default_list[6])),
            (key_default_list[7], 'choice', 'true,false,-', 'CRL Sign', '-', common.check_ext_key_usage(keylist,key_default_list[7])),
            (key_default_list[8], 'choice', 'true,false,-', 'Encipher Only', '-', common.check_ext_key_usage(keylist,key_default_list[8])),
            (key_default_list[9], 'choice', 'true,false,-', 'Decipher Only', '-', common.check_ext_key_usage(keylist,key_default_list[9]))]            

    common.constraint_attributes(constraint_definition, keyUsageExtConstraintImpl_attributes)

def keyConstraintImpl(Policy_Value):

    constraint_definition = etree.SubElement(Policy_Value, 'constraint', id='Key Constraint')
    s1 = 'This constraint accepts the key only if Key Type=-, Key Parameters =1024,2048,3072,4096,nistp256,nistp384,nistp521'
    constraint_description = etree.SubElement(constraint_definition, 'description').text = s1
    constraint_classid = etree.SubElement(constraint_definition, 'classId').text = 'keyConstraintImpl'
    s2 = 'Key Lengths or Curves. For EC use comma separated list of curves, otherise use list of key sizes. Ex: 1024,2048,4096,8192 or:'
    s3 = 'nistp256,nistp384,nistp521,sect163k1,nistk163 for EC.'

    keyConstraintImpl_attributes = [
            ('keyType', 'choice','-,RSA,EC', 'Key Type', 'RSA', '-'),
            ('keyParameters', 'string', 'NULL', s2 + s3, 'NULL', '1024,2048,3072,4096,nistp256,nistp384,nistp521')]

    common.constraint_attributes(constraint_definition, keyConstraintImpl_attributes)


