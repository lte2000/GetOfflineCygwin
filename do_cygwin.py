#!/usr/bin/env python

import argparse
import yaml
import logging
import os
import subprocess
import sys
import re
import hashlib

mylogger = logging.getLogger("DoCygwin")

DEF_SOURCE = "http://mirrors.ustc.edu.cn/cygwin/"
DEF_TARGET = "D:\\temp\\cygwin\\"
DEF_ARIA2C = r".\aria2c.exe"
DEF_CUSTOMPACKAGES = "cygwinpackage.yaml"
DEF_LOGFILE = "docygwin.log"

class NegateAction(argparse.Action):
    def __call__(self, parser, ns, values, option):
        setattr(ns, self.dest, option[2:4] != 'no')

parser = argparse.ArgumentParser()
parser.add_argument("--source", dest="source", default=DEF_SOURCE, help="(mirror) URL to download cygwin. Default is {}".format(DEF_SOURCE))
parser.add_argument("--target", dest="target", default=DEF_TARGET, help="target local dir for cygwin download. Default is {}".format(DEF_TARGET))
parser.add_argument("--aria2c", dest="aria2c", default=DEF_ARIA2C, help="location of aria2c.exe. Default is {}".format(DEF_ARIA2C))
parser.add_argument("--skip64", "--noskip64", dest="skip64", action=NegateAction, default=False, nargs=0, help="skip x86_64 packages process")
parser.add_argument("--skip32", "--noskip32", dest="skip32", action=NegateAction, default=False, nargs=0, help="skip x86 packages process")
parser.add_argument("--validate", dest="validate", action='store_true', help="to validate local packages instead of download")
parser.add_argument("--novalidatedigest", "--validatedigest", dest="validatedigest", action=NegateAction, default=True, nargs=0, help="don't validate the package's digest")
parser.add_argument("--deleteorphans", "--nodeleteorphans", dest="deleteorphans", action=NegateAction, default=False, nargs=0, help="remove orphaned package and empty directory during validation")
parser.add_argument("--showpackageinfo", dest="showpackageinfo", action='store_true', help="print category and package information and quit")
parser.add_argument("--skipsetup", "--noskipsetup", dest="skipsetup", action=NegateAction, default=False, nargs=0, help="skip setup files process")
parser.add_argument("--skipdlsetup", "--noskipdlsetup", dest="skipdlsetup", action=NegateAction, default=False, nargs=0, help="no real download action for setup files")
parser.add_argument("--skippackage", "--noskippackage", dest="skippackage", action=NegateAction, default=False, nargs=0, help="skip packages process")
parser.add_argument("--skipdlpackage", "--noskipdlpackage", dest="skipdlpackage", action=NegateAction, default=False, nargs=0, help="no real download action for packages")
parser.add_argument("--skipdlexist", "--noskipdlexist", dest="skipdlexist", action=NegateAction, default=False, nargs=0, help="don't download if the package exist and validation is correct")
parser.add_argument("--custompackages", dest="custompackages", default=DEF_CUSTOMPACKAGES, metavar="FILE",
                    help="file for custom specified categories and packages which to be included or excluded. Defaut is {}".format(DEF_CUSTOMPACKAGES))
parser.add_argument("--setupproxy", dest="setupproxy", metavar="PROXY", help="proxy to be used only for setup files download")
parser.add_argument("--verbose", "-v", dest="verbose", action="count", help="display detailed information")
parser.add_argument('--version', action='version', version='%(prog)s v2.0')
parser.add_argument('--warnofobsolete', action=NegateAction, default=False, nargs=0, help="warn if obsoleted package is added")
parser.add_argument('--log', dest="logfile", default=DEF_LOGFILE, help="log file name. Default is {}".format(DEF_LOGFILE))


class DoCygwin(object):
    ARCH_SETUP = ("setup.ini", "setup.bz2", "setup.xz")
    
    def __init__(self, options):
        self.options = options
        if not self.options.source.endswith('/'):
            self.options.source += '/'
        self.custom_package = {"include_category":[], "exclude_category":[], "include_package":[], "exclude_package":[]}
        self.include_packages = {"x86":{}, "x86_64":{}}
        self.exclude_packages = {"x86": {}, "x86_64": {}}
        self.setup_packages = {"x86": {}, "x86_64": {}}
        self.debug = self.options.verbose >= 3
        self.logger = logging.getLogger("DoCygwin")
        fh = logging.FileHandler(self.options.logfile, mode="w")
        formatter = logging.Formatter('%(levelname)s: %(message)s')
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)
        self.logger.setLevel(logging.DEBUG)
        if self.debug:
            self.logger.debug("options: {}".format(self.options))
    
    def load_custompackage_info(self):
        with open(self.options.custompackages) as f:
            self.custom_package = yaml.safe_load(f)
        if self.debug:
            self.logger.debug("custom_package: {}".format(self.custom_package))
    
    def download_setup_files(self):
        cmd = "_get_setup.cmd"
        arch_setup_files = list(self.ARCH_SETUP) + [x+".sig" for x in self.ARCH_SETUP]
        root_setup_files = []
        proxy = " -j1 --all-proxy="+self.options.setupproxy if self.options.setupproxy is not None else ""
        with open(cmd, "w") as f:
            for arch in ("x86", "x86_64"):
                if (arch == "x86" and self.options.skip32) or (arch == "x86_64" and self.options.skip64):
                    continue
                f.write("{} -Z --conf-path=aria2c.conf -d{} {}\n".format(
                    self.options.aria2c,
                    os.path.join(self.options.target, arch),
                    " ".join(["{}{}/{}".format(self.options.source, arch, x) for x in arch_setup_files]))
                )
                root_setup_files += ["https://cygwin.com/setup-{arch}.exe https://cygwin.com/setup-{arch}.exe.sig".format(arch=arch)]
            if root_setup_files:
                f.write("{} -Z --conf-path=aria2c.conf{} -d{} {}\n".format(
                    self.options.aria2c,
                    proxy,
                    self.options.target,
                    " ".join(root_setup_files))
                )
        if not self.options.skipdlsetup:
            try:
                subprocess.check_call(cmd, shell=True)
            except subprocess.CalledProcessError as e:
                self.logger.error(e)
                sys.exit(1)
        else:
            self.logger.warn("skipdlsetup is True, setup file download is not launched")

    def validate_setup_files(self):
        file_to_verify = []
        for arch in ("x86", "x86_64"):
            if (arch == "x86" and self.options.skip32) or (arch == "x86_64" and self.options.skip64):
                continue
            file_to_verify.append(os.path.join(self.options.target, "setup-{}.exe.sig".format(arch)))
            file_to_verify += [os.path.join(self.options.target, arch, x+".sig") for x in self.ARCH_SETUP]
        for f in file_to_verify:
            cmd = "gpgv --keyring {} {}".format(os.path.join(".", "cygwin.gpg"), f)
            if self.debug:
                self.logger.debug("cmd: {}".format(cmd))
            try:
                subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True)
            except subprocess.CalledProcessError as e:
                self.logger.error(e)
                self.logger.error(e.output)
                sys.exit(1)

    def load_setup_ini(self, file):
        data = {}
        package_node = None
        with open(file) as f:
            lines = f.readlines()
        lineno = 0
        while lineno < len(lines):
            line = lines[lineno]
            lineno += 1
            match = re.match(r"^@\s+(\S+)", line)
            if match: # start a new package
                data[match.group(1)] = package_node = {}
                current_node = package_node
                version_list = None
                continue
            if package_node is None:
                continue
            match = re.match(r"^\[([^\]]+)\]", line)
            if match:
                if version_list is None:
                    package_node["version_list"] = version_list = []
                current_node = {}
                version_list.append({match.group(1):current_node})
                continue
            match = re.match(r"^(sdesc|ldesc|category|Section|message|requires|replace-versions|"
                             r"version|install|source|Source|depends2|obsoletes|build-depends):\s*(.*)", line)
            if match:
                key = match.group(1)
                value = match.group(2)
                if key in ("sdesc", "ldesc", "message"):
                    while not value.endswith('\"') or value == '\"':  # start line only have a \", though it end with \", it is not the end line.
                        value += "\n" + lines[lineno].rstrip()
                        lineno += 1
                current_node[key] = value
            else:
                if line.rstrip() == "":
                    continue
                raise Exception("Unrecognized line in '{}', line {}:\n{}".format(file, lineno, line))
        
        # check if package has no current version info, use [test] or last [prev]
        for name, attr in data.items():
            if attr.has_key("install"):
                continue
            last_test = last_prev = None
            for ver in attr["version_list"][::-1]:
                for k, v in ver.items():
                    if k == "test":
                        last_test = v
                        break
                    elif k == "prev":
                        if last_prev is None:
                            last_prev = v
                if last_test is not None:
                    break
            if last_test is not None:
                self.logger.warn("file '{}' package '{}' has no current version info, will use [test] instead.".format(file, name))
                for k, v in last_test.items():
                    attr[k] = v
            elif last_prev is not None:
                self.logger.warn("file '{}' package '{}' has no current version info, will use last [prev] instead.".format(file, name))
                for k, v in last_prev.items():
                    attr[k] = v
            else:
                raise Exception("file '{}' package '{}' has no version info.".format(file, name))
        
        # extract info into fields
        for name, attr in data.items():
            attr["_path"], size, attr["_checksum"] = attr["install"].split()
            attr["_size"] = int(size)
            attr["_category"] = attr["category"].split()
            attr["_requires"] = attr["requires"].split() if attr.has_key("requires") else []
        
        return data

    def _match_package_name(self, name, name_list):
        for pattern in name_list:
            if pattern.startswith("reg:"):
                if re.match(pattern[4:], name):
                    return True
            else:
                if name == pattern:
                    return True
        
        return False
    
    def _union_two_package(self, pkg1, pkg2, pkg2_suffix):
        union_package = pkg1.copy()
        for name, attr in pkg2.items():
            try:
                if not union_package.has_key(name):
                    union_package[name] = attr
                elif union_package[name]["install"] != attr["install"]:
                    self.logger.info("Package '{}' exists in both x86 and x86_64, with different path:\n    {}\n    {}".format(
                        name, union_package[name]["install"], attr["install"]
                    ))
                    union_package[name+pkg2_suffix] = attr
            except KeyError as e:
                self.logger.critical("'{}', 'install' key error".format(name))
                raise
        return union_package
        
    def generate_package_list(self):
        for arch in ("x86", "x86_64"):
            if (arch == "x86" and self.options.skip32) or (arch == "x86_64" and self.options.skip64):
                continue
            all_packages = self.load_setup_ini(os.path.join(self.options.target, arch, "setup.ini"))
            self.setup_packages[arch] = all_packages
            included_package = {}
            excluded_package = {}
            for name, attr in all_packages.items():
                to_be_included = None
                for _ in range(1):
                    if self._match_package_name(name, self.custom_package["include_package"]):
                        to_be_included = True
                        break
                    if self._match_package_name(name, self.custom_package["exclude_package"]):
                        to_be_included = False
                        break
                    to_be_included = False
                    for category in attr["_category"]:
                        if category in self.custom_package["include_category"]:
                            to_be_included = True
                            break
                        if category not in self.custom_package["exclude_category"]:
                            to_be_included = True
                            break
                if to_be_included:
                    included_package[name] = attr
                else:
                    excluded_package[name] = attr
            
            # re-include excluded packages if they're required by some packages (in requires section)
            package_list_modified = True
            while package_list_modified:
                package_list_modified = False
                for name, attr in included_package.items():
                    for required_package in attr["_requires"]:
                        if not included_package.has_key(required_package):
                            included_package[required_package] = excluded_package[required_package]
                            del excluded_package[required_package]
                            self.logger.info("{} package '{}' is added as required by {}".format(
                                arch, required_package, name
                            ))
                            if self.options.warnofobsolete:
                                if "_obsolete" in included_package[required_package]["_category"]:
                                    self.logger.info("    {} is in category '{}' containing _obsolete!".format(
                                        required_package, included_package[required_package]["category"]
                                    ))
                            package_list_modified = True
            
            self.include_packages[arch] = included_package
            self.exclude_packages[arch] = excluded_package
        
        # combine x86, x86_64 package list, so common part can download only once
        self.include_packages["union"] = self._union_two_package(self.include_packages["x86"], self.include_packages["x86_64"], "[x86_64]")
        self.exclude_packages["union"] = self._union_two_package(self.exclude_packages["x86"], self.exclude_packages["x86_64"], "[x86_64]")

    def _print_packages_info(self, pkgs_type, include_pkgs, exclude_pkgs=None, info=["category"]):
        totalsize = 0
        categorysize = {}
        categorycount = {}
        categorycontent = {}
        for name, attr in include_pkgs.items():
            totalsize += attr["_size"] 
            for category in attr["_category"]:
                categorycount[category] = categorycount.get(category, 0) + 1
                categorysize[category] = categorysize.get(category, 0) + attr["_size"] 
                if categorycontent.has_key(category):
                    categorycontent[category].append(name)
                else:
                    categorycontent[category] = [name]
        print "#" * 79
        print "{} information:".format(pkgs_type)
        print "Total size: {:,d}".format(totalsize)
        if "category" in info:
            print "-" * 20
            print "Category:"
            for category in sorted(categorycount.keys()):
                print "    {:>20}: count: {:>4}  size {:>14,d}".format(category, categorycount[category], categorysize[category])
        if "package_in_category" in info:
            for category in sorted(categorycount.keys()):
                print "-" * 20
                print "Packages in category {}:".format(category)
                for package in sorted(categorycontent[category], cmp=lambda x, y: cmp(x.upper(), y.upper())):
                    print "    {:<50}: {:>11,d}".format(package, include_pkgs[package]["_size"])
        if "package" in info:
            print "-" * 20
            print "Packages (sort by name):"
            for package in sorted(include_pkgs.keys(), cmp=lambda x,y:cmp(x.upper(),y.upper())):
                print "    {:<50}: {:>11,d}".format(package, include_pkgs[package]["_size"])
            print "-" * 20
            print "Packages (sort by size):"
            for package in sorted(include_pkgs.keys(), cmp=lambda x,y:cmp(include_pkgs[x]["_size"], include_pkgs[y]["_size"])):
                print "    {:>50}: {:>11,d}".format(package, include_pkgs[package]["_size"])
        if "exclude_package" in info and exclude_pkgs is not None:
            print "-" * 20
            print "Packages excluded:"
            for package in sorted(exclude_pkgs.keys(), cmp=lambda x,y:cmp(x.upper(),y.upper())):
                print "    {:<50}: {:>11,d} {}".format(package, exclude_pkgs[package]["_size"], exclude_pkgs[package]["sdesc"])

    def print_package_info(self):
        if self.options.verbose >= 1:
            info = ["category"]
        if self.options.verbose >= 3:
            info.append("package_in_category")
        self._print_packages_info("setup_x86", self.setup_packages["x86"], info=info)
        self._print_packages_info("setup_x86_64", self.setup_packages["x86_64"], info=info)
        self._print_packages_info("x86_to_download", self.include_packages["x86"], self.exclude_packages["x86"], info=info)
        self._print_packages_info("x86_64_to_download", self.include_packages["x86_64"], self.exclude_packages["x86_64"], info=info)
        self._print_packages_info("union_to_download", self.include_packages["union"], self.exclude_packages["union"], info=info)
        
        if self.options.verbose >= 1:
            info = ["package"]
        if self.options.verbose >= 2:
            info.append("exclude_package")
        self._print_packages_info("setup_x86", self.setup_packages["x86"], info=info)
        self._print_packages_info("setup_x86_64", self.setup_packages["x86_64"], info=info)
        self._print_packages_info("x86_to_download", self.include_packages["x86"], self.exclude_packages["x86"], info=info)
        self._print_packages_info("x86_64_to_download", self.include_packages["x86_64"], self.exclude_packages["x86_64"], info=info)
        self._print_packages_info("union_to_download", self.include_packages["union"], self.exclude_packages["union"], info=info)

    def _validate_package(self, filename, expected_checksum, expected_size):
        if self.options.validatedigest:
            with open(filename, "rb") as f:
                if hashlib.sha512(f.read()).hexdigest() != expected_checksum:
                    return "checksum mismatch"
                else:
                    return "OK"
        else:
            if os.path.getsize(filename) != expected_size:
                return "size mismatch"
            else:
                return "OK"
        
    def _get_local_absolute_path(self, rel_path):
        filename = rel_path
        if os.sep == "\\":
            filename = filename.replace("/", "\\")
        return os.path.join(self.options.target, filename)
        
    def validate_packages(self):
        errorcnt = 0
        all_path = []
        for name, attr in self.include_packages["union"].items():
            filename = self._get_local_absolute_path(attr["_path"])
            all_path.append(filename)
            if not os.path.exists(filename):
                self.logger.error("{} is NOT FOUND!".format(filename))
                errorcnt += 1
            else:
                res = self._validate_package(filename, attr["_checksum"], attr["_size"])
                if res == "OK":
                    self.logger.info("{} validation OK")
                else:
                    self.logger.error("{} {}!".format(filename, res))
                    errorcnt += 1

        # check orhpan files
        # add setup files
        for arch in ("x86", "x86_64"):
            if (arch == "x86" and self.options.skip32) or (arch == "x86_64" and self.options.skip64):
                continue
            arch_setup_files = list(self.ARCH_SETUP) + [x + ".sig" for x in self.ARCH_SETUP]
            for f in arch_setup_files:
                all_path.append(os.path.join(self.options.target, arch, f))
            all_path.append(os.path.join(self.options.target, "setup-{}.exe".format(arch)))
            all_path.append(os.path.join(self.options.target, "setup-{}.exe.sig".format(arch)))
        for dirpath, dirnames, filenames in os.walk(self.options.target, topdown=False):
            for file in filenames:
                filename = os.path.join(dirpath, file)
                if filename not in all_path:
                    if self.options.deleteorphans:
                        self.logger.warning("Unused file '{}' will be deleted!".format(filename))
                        os.unlink(filename)
                    else:
                        self.logger.warning("Unused file '{}' found".format(filename))
            for dir in dirnames:
                dirname = os.path.join(dirpath, dir)
                if len(os.listdir(dirname)) == 0:
                    if self.options.deleteorphans:
                        self.logger.warning("Empty directory '{}' will be deleted!".format(dirname))
                        os.rmdir(dirname)
                    else:
                        self.logger.warning("Empty directory '{}' found".format(dirname))
        if errorcnt:
            self.logger.error("There're {} errors during package validation. Check the log!".format(errorcnt))
        else:
            print "All packages are correct."
        return errorcnt

    def download_packages(self):
        cmd = "_get_package.cmd"
        cmd_in = "_get_package.in"
        cmd_session = "_get_package.session"
        with open(cmd_in, "w") as f:
            for name, attr in self.include_packages["union"].items():
                skipit = False
                filename = self._get_local_absolute_path(attr["_path"])
                if self.options.skipdlexist and os.path.exists(filename):
                    res = self._validate_package(filename, attr["_checksum"], attr["_size"])
                    if res == "OK":
                        skipit = True
                    else:
                        self.logger.warn("{} {}, will download again".format(filename, res))
                if skipit:
                    comment = "#"
                else:
                    comment = ""
                f.write("{}{}{}\n".format(comment, self.options.source, attr["_path"]))
                dirname = os.path.dirname(filename)
                f.write("{}  dir={}\n".format(comment, dirname))
        with open(cmd, "w") as f:
            f.write("{} --conf-path=aria2c.conf --save-session={} -i{}".format(self.options.aria2c, cmd_session, cmd_in))
        
        if not self.options.skipdlpackage:
            try:
                subprocess.check_call(cmd, shell=True)
            except subprocess.CalledProcessError as e:
                self.logger.error(e)
                self.logger.error("There're some files unfinished. Please run\n"
                                  "    {} --conf-path=aria2c.conf -i{}".format(self.options.aria2c, cmd_session))
                sys.exit(1)
        else:
            self.logger.warn("skipdlpackage is True, package download is not launched")
    
    def main_process(self):
        self.load_custompackage_info()
        if self.options.validate:
            self.validate_setup_files()
            if not self.options.skippackage:
                self.generate_package_list()
                self.validate_packages()
        elif self.options.showpackageinfo:
            self.validate_setup_files()
            self.generate_package_list()
            self.print_package_info()
        else:
            if not self.options.skipsetup:
                self.download_setup_files()
            self.validate_setup_files()
            if not self.options.skippackage:
                self.generate_package_list()
                self.download_packages()
        
if __name__ == "__main__":
    # create console handler
    formatter = logging.Formatter('%(levelname)s: %(message)s')
    consoleHandle = logging.StreamHandler()
    consoleHandle.setLevel(logging.WARNING)
    consoleHandle.setFormatter(formatter)
    mylogger.addHandler(consoleHandle)

    dlcygwin = DoCygwin(parser.parse_args())
    dlcygwin.main_process()
