# mscp/generate/mapping.py

# Standard python modules
import argparse
import re
import sys
import csv
import os
import yaml
import glob
from pathlib import Path
from typing import Any

# Local python modules
from ..classes import Author, Baseline, Macsecurityrule
from ..common_utils import config, get_version_data, make_dir, mscp_data, open_file
from ..common_utils.logger_instance import logger

# Additional python modules


def update_rule_with_custom_controls(
    rule: Macsecurityrule, controls: list[str], header: str
) -> None:
    """
    Update a rule with custom controls and add references.

    Args:
        rule (Macsecurityrule): The rule to update.
        controls (List[str]): The controls to add.
        header (str): The header to map controls against.
    """

    if not rule.references.custom_refs:
        rule.references["custom_refs"] = {}

    rule.references["custom_refs"][header] = controls
    logger.info(f"Updated rule {rule.rule_id} with controls: {controls}")



def generate_mapping(args: argparse.Namespace) -> None:
    current_version_data: dict[str, Any] = get_version_data(
        args.os_name, args.os_version, mscp_data
    )

    rules: list[Macsecurityrule] = Macsecurityrule.collect_all_rules(
        args.os_name, args.os_version
    )
    print(args)
    custom_rules: list[Macsecurityrule] = []
    print(args)
    # csv_data: dict[str, Any] = open_file(args.csv)
    for rule in rules:
        # sub_directory = rule.split(".yaml")[0].split("/")[2]
        sub_directory = rule.rule_id.split("_")[0]
        if sub_directory == "system":
            sub_directory = "system_settings"
        
        if "supplemental" in rule or "srg" in rule:
            continue

        # with open(rule) as r:
        #     rule_yaml = yaml.load(r, Loader=yaml.SafeLoader)
        rule_yaml = rule

        control_array = []
        # print("----------------------")
        # print(rule_yaml)
        # print()
        with open(args.csv, newline='',encoding='utf-8-sig') as csvfile:
            csv_reader = csv.DictReader(csvfile,dialect='excel')
            modded_reader = csv_reader
            dict_from_csv = dict(list(modded_reader)[0])


            list_of_column_names = list(dict_from_csv.keys())


            nist_header = list_of_column_names[1]
            other_header = list_of_column_names[0]            

        with open(args.csv, newline='',encoding='utf-8-sig') as csvfile:
            reader = csv.DictReader(csvfile,dialect='excel')

            for row in reader:

                if args.framework != nist_header:
                    sys.exit(str(args.framework) + " not found in CSV")                
                if "N/A" in row[nist_header]:
                    continue

                controls = row[nist_header].split(',')

                duplicate = ""
                csv_duplicate = ""
                for control in controls:

                        try:

                            rule_yaml['references']
                            
                            if "/" in str(args.framework):

                                framework_main = args.framework.split("/")[0]                                
                                framework_sub = args.framework.split("/")[1]
                                

                                references = []
                                
                                # if "custom_refs" not in rule_yaml['references']:
                                if rule_yaml['references']['custom_refs'] is None:
                                    
                                    references = rule_yaml.references[framework_main][framework_sub]
                                
                                    if framework_sub == "800-53r5" or "800-171r3":
                                        framework_sub = "nist_{}".format(framework_sub.replace("-","_"))
                                    
                                        references = rule_yaml.references[framework_main][framework_sub]
                                        
                                        
                                else:
                                    references = rule_yaml['references']['custom_refs'][framework_main][framework_sub]

                                for yaml_control in references:
                                    if duplicate == str(yaml_control).split("(")[0]:
                                        continue
                                    if csv_duplicate == str(row[other_header]):

                                        continue
                                    if control.replace(" ",'') == str(yaml_control):

                                        duplicate = str(yaml_control).split("(")[0]
                                        csv_duplicate = str(row[other_header])

                                        row_array = str(row[other_header]).split(",")
                                        for item in row_array:
                                            control_array.append(item)
                                            print(rule_yaml['rule_id'] + " - " + str(args.framework) + " " + str(yaml_control) + " maps to " + other_header + " " + item)


                            else:
                                
                                references = []
                                # if "custom" not in rule_yaml['references']:
                                
                                if rule_yaml['references']['custom_refs'] is None:
                                    # framework = args.framework
                                    framework_main = "nist"
                                    if args.framework == "disa_stig" or args.framework == "cci" or args.framework == "srg" or args.framework == "cmmc" or args.framework == "sfr":
                                        framework_main = "disa"
                                    if args.framework == "benchmark" or args.framework == "controls_v8":
                                        framework_main = "cis"
                                    if args.framework == "indigo":
                                        framework_main = "bsi"
                                    framework_sub = args.framework
                                
                                    if args.framework == "800-53r5" or "800-171r3":
                                    #     framework = "nist_{}".format(args.framework.replace("-","_"))
                                        framework_sub = "nist_{}".format(args.framework.replace("-","_"))
                                    
                                    
                                    references = rule_yaml['references'][framework_main][framework_sub]
                                    
                                else:
                                    references = rule_yaml['references']['custom_refs'][args.framework]

                                for yaml_control in references:                                    
                                    if duplicate == str(yaml_control).split("(")[0]:
                                        continue
                                    if csv_duplicate == str(row[other_header]):
                                        continue

                                    if control.replace(" ",'') == str(yaml_control):
                                        duplicate = str(yaml_control).split("(")[0]
                                        csv_duplicate = str(row[other_header])
                                        row_array = str(row[other_header]).split(",")
                                        for item in row_array:
                                            control_array.append(item)
                                            print(rule_yaml['rule_id'] + " - " + str(args.framework) + " " + str(yaml_control) + " maps to " + other_header + " " + item)

                        except:
                            continue

        if len(control_array) == 0:
            continue

        custom_rule = '''references:
    {}:'''.format(other_header)

        for control in control_array:
            custom_rule = custom_rule + '''
      - {}'''.format(control)

        custom_rule = custom_rule + '''
tags:
  - {}'''.format(other_header)
        
        output_dir: Path = Path(config["output_dir"], other_header.lower())

        rule_path = output_dir / "rules" / sub_directory
        rule_path.mkdir(parents=True, exist_ok=True)

        try:
            with open(str(rule_path) + "/" + rule_yaml['rule_id'] + ".yaml", 'w') as r:
                custom_yaml = r.read()

                custom_yaml = custom_yaml.replace(other_header + ": ", custom_rule)
                with open(str(rule_path) + "/" + rule_yaml['rule_id'] + ".yaml", 'w') as fw:
                    fw.write(custom_yaml)
        except:
                with open(str(rule_path) + "/" + rule_yaml['rule_id'] + ".yaml", 'w') as fw:
                    fw.write(custom_rule)

        audit = []
        auth = []
        icloud = []
        os_section = []
        pwpolicy = []
        system_settings = []
        sysprefs = []
        inherent = []
        na = []
        perm = []

        for rule in glob.glob(str(output_dir) + '/rules/*/*.yaml'):
            if "supplemental" in rule or "srg" in rule or "baseline" in rule:
                continue
            with open(rule) as r:
                custom_rule = yaml.load(r, Loader=yaml.SafeLoader)
                
                rule_id = rule.split(".yaml")[0].split("/")[-1]


                if other_header in custom_rule['tags']:
                    if "inherent" in rule_yaml['tags']:
                        inherent.append(rule_id)
                        continue
                    if "permanent" in custom_rule['tags']:
                        perm.append(rule_id)
                        continue
                    if "n_a" in custom_rule['tags']:
                        na.append(rule_id)
                        continue
                    if "/audit/" in rule:
                        audit.append(rule_id)
                        continue
                    if "/auth/" in rule:
                        auth.append(rule_id)
                        continue
                    if "/icloud/" in rule:
                        icloud.append(rule_id)
                        continue
                    if "/os/" in rule:
                        os_section.append(rule_id)
                        continue
                    if "/pwpolicy/" in rule:
                        pwpolicy.append(rule_id)
                        continue
                    if "/system_settings/" in rule:
                        system_settings.append(rule_id)
                        continue
                    if "/settings/" in rule:
                        sysprefs.append(rule_id)
                        continue


        full_baseline = '''title: "{1} {2}: Security Configuration - {0}"
description: |
This guide describes the actions to take when securing a {1} {2} system against the {0}.
authors:
- name: (ENTER AUTHOR NAME)
  organization: (ENTER ORG NAME)
parent_values: recommended
platform:
  os: {1}
  version: {2}
profile:'''.format(other_header,args.os_name,args.os_version)

        if len(audit) != 0:

            full_baseline = full_baseline + '''
- section: Auditing
  rules:'''
            audit.sort()

            for rule in audit:
                full_baseline = full_baseline + '''
  - {}'''.format(rule)
        if len(auth) != 0:
            full_baseline = full_baseline + '''
- section: Authentication
  rules:'''
            auth.sort()

            for rule in auth:
                full_baseline = full_baseline + '''
  - {}'''.format(rule)

        if len(system_settings) != 0:
            full_baseline = full_baseline + '''
- section: System Settings
  rules:'''
            system_settings.sort()

            for rule in system_settings:
                full_baseline = full_baseline + '''
  - {}'''.format(rule)

        if len(icloud) != 0:
            full_baseline = full_baseline + '''
- section: iCloud
  rules:'''
            icloud.sort()
            for rule in icloud:
                full_baseline = full_baseline + '''
  - {}'''.format(rule)
                
        if len(os_section) != 0 and args.os_name == "os":
            full_baseline = full_baseline + '''
- section: Operating System
  rules:'''
            os_section.sort()
            for rule in os_section:
                full_baseline = full_baseline + '''
  - {}'''.format(rule)

        if len(pwpolicy) != 0:
            full_baseline = full_baseline + '''
- section: Password Policy
  rules:'''
            pwpolicy.sort()
            for rule in pwpolicy:
                full_baseline = full_baseline + '''
  - {}'''.format(rule)

        if len(inherent) != 0:
            full_baseline = full_baseline + '''
- section: Inherent
  rules:'''
            inherent.sort()
            for rule in inherent:
                full_baseline = full_baseline + '''
  - {}'''.format(rule)

        if len(perm) != 0:
            full_baseline = full_baseline + '''
- section: Permanent
  rules:'''
            perm.sort()
            for rule in perm:
                full_baseline = full_baseline + '''
  - {}'''.format(rule)

        if len(na) != 0:
            full_baseline = full_baseline + '''
- section: Not Applicable
  rules:'''
            na.sort()
            for rule in na:
                full_baseline = full_baseline + '''
  - {}'''.format(rule)

#         listofsupplementals = str()
#         for supp_rule in glob.glob('../rules/supplemental/*.yaml',recursive=True):
#             listofsupplementals = listofsupplementals + '''- {}
#         '''.format(os.path.basename(supp_rule).split(".")[0])
#         full_baseline = full_baseline + '''
# - section: Supplemental
#   rules:
#         {}
#         '''.format(listofsupplementals)

    try:
        output_dir: Path = Path(config["output_dir"], other_header.lower())

        baseline_path = output_dir / "baselines"
        baseline_path.mkdir(parents=True, exist_ok=True)

        
        with open(str(baseline_path) + "/" + other_header.lower().replace(" ","_") + ".yaml",'w') as fw:
            fw.write(full_baseline)
            print(other_header.lower().replace(" ","_") + ".yaml baseline file created in build/" + other_header + "/baseline/")

        print("Move all of the folders in rules into the custom folder.")
    except:
        print("No controls mapped were found in rule files.")        

    # print(args.csv)
    # if len(csv_data.keys()) < 2:
    #     print(len(csv_data.keys()))
    #     print(csv_data.keys())
    #     logger.error("The CSV File can only contain 2 headers.")
    #     sys.exit()

    # other_header, framework_header = csv_data.keys()

    # if args.framework not in framework_header:
    #     logger.error(f"{args.framework} not found in csv file.")
    #     sys.exit()

    # baseline_name: str = other_header.replace(" ", "_").lower()
    # output_dir: Path = Path(config["output_dir"], other_header.lower())
    # baseline_file_path: Path = output_dir / "baseline" / f"{baseline_name}.yaml"

    # if not output_dir.exists():
    #     make_dir(output_dir)

    # for rule in rules:
    #     rule_file_path: Path = output_dir / "rules" / f"{rule.rule_id}.yaml"
    #     control_list: list = []

    #     if any(tag in rule.tags for tag in ["supplemental", "srg"]):
    #         continue

    #     for row in csv_data.values():
    #         if "N/A" in row.get(args.framework):
    #             continue

    #         controls: list[str] = [
    #             control.strip() for control in row[args.framework].split(",")
    #         ]
    #         references: list = []

    #         match args.framework:
    #             case var if re.search(r"/", var):
    #                 framework_main, framework_sub = (
    #                     args.framework.split("/", 1) + [None][:2]
    #                 )

    #                 if rule.customized:
    #                     references = (
    #                         rule.references.get("custom_refs", {})
    #                         .get(framework_main, {})
    #                         .get(framework_sub, [])
    #                     )
    #                 else:
    #                     references = rule.references.get(framework_main, {}).get(
    #                         framework_sub, []
    #                     )
    #             case _:
    #                 references = rule.references.get(args.framework, [])

    #         for control in controls:
    #             if control in references and control not in control_list:
    #                 control_list.append(control)
    #                 row_array = [item.strip() for item in row[other_header].split(",")]

    #                 for item in row_array:
    #                     logger.info(
    #                         f"{rule.rule_id} - {args.framework} {control} maps to {other_header} {item}"
    #                     )

    #     if not control_list:
    #         logger.debug(f"No controls matched for rule {rule.rule_id}")
    #         continue

    #     update_rule_with_custom_controls(rule, control_list, other_header)

    #     if not rule.customized:
    #         rule.customized = True

    #     rule.tags.append(other_header)

    #     rule.to_yaml(rule_file_path)

    #     custom_rules.append(rule)

    # baseline_title: str = (
    #     f"{args.os_name} {args.os_version}: Security Configuration - {args.framework}"
    # )

    # Baseline.create_new(
    #     baseline_file_path,
    #     custom_rules,
    #     current_version_data,
    #     baseline_name,
    #     [Author(name=None, organization=None)],
    #     baseline_title,
    # )
