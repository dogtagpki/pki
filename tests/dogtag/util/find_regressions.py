#!/usr/bin/python

import sys
from lxml import etree

### Usage python find_regressions.py <old_log.xml> <new_log.xml>

doc = etree.parse(str(sys.argv[1]))

tasks = doc.xpath("/job/recipeSet/recipe/task")
task_results = dict()
result_status = None

for task in tasks:
    task_name = task.attrib['name']
    results = task.xpath("results/result")
    if results is not None:
        result_status = dict()
    for result in results:
        result_status[result.attrib['path']] = result.attrib['result']

    task_results[task_name] = result_status
    result_status = None

## Compare the new ones

doc = etree.parse(str(sys.argv[2]))

tasks = doc.xpath("/job/recipeSet/recipe/task")

pass_to_fail = []
fail_to_pass = []

for task in tasks:
    task_name = task.attrib['name']
    curr_results = task.xpath("results/result")
    old_results = task_results[task_name]
    if curr_results is not None:
        for result in curr_results:
            if result.attrib['result'] != old_results[result.attrib['path']]:
                 if result.attrib['result'] == "Fail":
                     fail_to_pass.append(result.attrib['path'])
                 else:
                     pass_to_fail.append(result.attrib['path'])
if len(pass_to_fail) == 0 and len(fail_to_pass) == 0:
    sys.exit(1)

with open("regressions.txt", "w") as f:
    if len(pass_to_fail) > 0:
        f.write("Regressions: " + str(pass_to_fail) + "\n")
    if len(fail_to_pass) > 0:
        f.write("Tests that pass with the new changes: " + str(fail_to_pass) + "\n")
