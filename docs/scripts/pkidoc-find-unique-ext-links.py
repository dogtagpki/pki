# pkidoc-find-unique-ext-links.py
# - ladycfu
#
# This script recursively searches all AsciiDoc (.adoc) files in a given directory,
# finds all unique external links of the form link:https://...,
# and prints each unique link along with the file names and line numbers where it appears.
# Optionally, results can be written to an output file.

import os
import re

def find_unique_external_links(directory):
    link_pattern = re.compile(r'link:(https?://[^\s\]]+)')
    link_locations = {}

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.adoc'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        for line_num, line in enumerate(f, start=1):
                            for match in link_pattern.findall(line):
                                if match not in link_locations:
                                    link_locations[match] = []
                                link_locations[match].append(f"{file} (line {line_num})")
                except Exception as e:
                    print(f"Error reading {file_path}: {e}")

    return link_locations

if __name__ == "__main__":
    target_dir = input("Enter the directory to search: ").strip()
    if not target_dir:
        print("No directory provided. Exiting.")
        exit(1)

    output_file = input("Enter output file name (leave blank to print to terminal): ").strip()
    link_locations = find_unique_external_links(target_dir)

    output_lines = ["Unique external links found and their locations:"]
    for link in sorted(link_locations):
        output_lines.append(f"{link}")
        for location in link_locations[link]:
            output_lines.append(f"  - {location}")

    if output_file:
        with open(output_file, 'w', encoding='utf-8') as out:
            for line in output_lines:
                out.write(line + "\n")
        print(f"Results written to {output_file}.")
    else:
        for line in output_lines:
            print(line)

