#! /usr/bin/python

import sys
from lxml import etree
from ConfigParser import ConfigParser


""" Parse the xml template and replace the values with the
    values from the configuration file passed.
    Usage: py modifybeakerjobxml.py <XML_TEMPLATE_PATH> <CONFIG_FILE_PATH>"""


doc = etree.parse(str(sys.argv[1]))

parser = ConfigParser()
parser.read(str(sys.argv[2]))

props=parser.defaults()

repos=props['repos']

if repos is not None:
    repos = str(repos).split()
    repos_element=doc.getroot().find('recipeSet/recipe/repos')
    i = 1
    for repo in repos:
        new_child = etree.SubElement(repos_element, 'repo', name='repo'+str(i), url=repo)
        i = i + 1

element = None
distro_family = props['distro_family']
if distro_family is not None:
    element=doc.find('recipeSet/recipe/distroRequires/and/distro_family')
    element.attrib['value'] = distro_family

distro_name = props['distro_name']
if distro_name is not None:
    element=doc.find('recipeSet/recipe/distroRequires/and/distro_name')
    element.attrib['value'] = distro_name

distro_arch = props['distro_arch']
if distro_arch is not None:
    element=doc.find('recipeSet/recipe/distroRequires/and/distro_arch')
    element.attrib['value'] = distro_arch

hostname = props['hostname']
if distro_family is not None:
    element=doc.find('recipeSet/recipe/hostRequires')
    etree.SubElement(element, 'hostname', op='=', value=hostname)

with open(str(sys.argv[1]), 'w') as outfile:
    doc.write(outfile)
