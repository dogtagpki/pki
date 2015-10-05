#!/usr/bin/python
# -*- coding: utf-8 -*
from lxml import etree

def policy_attributes(Policy_definition, policy_attributes):

    for idx,(name,syntax,constraint,description,defaultvalue) in enumerate(policy_attributes):
        policy_attribute_name = etree.SubElement(Policy_definition, 'policyAttribute', name=name)
        policy_attribute_descriptor = etree.SubElement(policy_attribute_name,'Descriptor')
        policy_attribute_syntax = etree.SubElement(policy_attribute_descriptor, 'Syntax').text = syntax
        if constraint != 'NULL':
            policy_attribute_constraint = etree.SubElement(policy_attribute_descriptor, 'Constraint').text=constraint
        policy_attribute_description = etree.SubElement(policy_attribute_descriptor, 'Description').text = description
        if defaultvalue != 'NULL':
            policy_attribute_defaultvalue = etree.SubElement(policy_attribute_descriptor, 'DefaultValue').text = defaultvalue
        else:
            policy_attribute_defaultvalue = etree.SubElement(policy_attribute_descriptor, 'DefaultValue')


def constraint_attributes(constraint_definition, constraint_attributes):

    for idx,(constraintid, syntax, constraint, description, defaultvalue, value) in enumerate(constraint_attributes):

        constraint_id = etree.SubElement(constraint_definition, 'constraint', id = constraintid)
        constraint_id_descriptor = etree.SubElement(constraint_id, 'descriptor')
        constraint_id_descriptor_syntax = etree.SubElement(constraint_id_descriptor, 'Syntax').text = syntax
        if constraint != 'NULL':
            constraint_id_descriptor_syntax = etree.SubElement(constraint_id_descriptor, 'Constraint').text = constraint

        constraint_id_descriptor_description = etree.SubElement(constraint_id_descriptor, 'Description').text = description

        if defaultvalue != 'NULL':
            constraint_id_descriptor_defaultvalue = etree.SubElement(constraint_id_descriptor, 'DefaultValue').text = defaultvalue

        if value != 'NULL':
            constraint_value = etree.SubElement(constraint_id, 'value').text = value
        else:
            constraint_value = etree.SubElement(constraint_id, 'value')

def policy_parameters(Policy_definition, parameters):

    for idx,(name, value) in enumerate(parameters):

        policy_param_name = etree.SubElement(Policy_definition, 'params', name=name)
        if value != 'NULL':
            policy_param_value = etree.SubElement(policy_param_name, 'value').text=value    
        else:
            policy_param_value = etree.SubElement(policy_param_name, 'value')

def policy_definition(Policy_Value,definition):

    Policy_definition = etree.SubElement(Policy_Value, 'def', id=definition['id'], classId=definition['classid'])
    Policy_description = etree.SubElement(Policy_definition, 'description').text = definition['description']

    return Policy_definition

def constraint_definition(Policy_Value, definition):

    constraint_definition = etree.SubElement(Policy_Value, 'constraint', id=definition['id'])
    constraint_description = etree.SubElement(constraint_definition, 'description').text = definition['description']
    constraint_classid = etree.SubElement(constraint_definition, 'classId').text = definition['classId']

    return constraint_definition        

def check_ext_key_usage(mylist, string):

    s1 = 'true'
    s2 = 'false'
    if string in mylist:
        return s1
    else:
        return s2

def get_policyId(root):

    Policy_Value = root.findall('./PolicySets/PolicySet/value')
    value = 0
    for key in Policy_Value:
       attributes = key.attrib
       value = attributes["id"]
    if value is 0:
       pvalue = '1'
    else:
       pvalue = int(value) + 1

    return str(pvalue)    

def get_Element_PolicyValue(PolicySet,javaclass):

    mydict = {}
    for key in PolicySet.iterchildren(tag='value'):
         PolicyValues=key.items()[0][1]
         classId=key[0].get('classId')
         mydict[classId]=PolicyValues

    if mydict.has_key(javaclass):
        value_Id = mydict[javaclass]
        Policy_value = PolicySet.find('./value[@id=' + "\"" +  str(value_Id) + "\"" + "]")
        return Policy_value
    else:
        return None

def check_policy(PolicySet, javaclass):

    DefinedPolicies = PolicySet.findall("./value/def")
    list_of_policy_classes = []
    for classes in DefinedPolicies:
        list_of_policy_classes.append(classes.get('classId'))

    # check if my classId is already there
    if javaclass in list_of_policy_classes:
        return True
    else:
        return False

