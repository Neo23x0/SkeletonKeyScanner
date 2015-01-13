# Skeleton Key Malware Scanner

Scanner for Skeleton Key Malware

Detection is based on four detection methods:

 1. File Name IOC 

 2. Yara Ruleset
    http://goo.gl/aAk3lN

 3. SHA1 hash check
    Compares known malicious SHA1 hashes with scanned files

The Windows binary is compiled with PyInstaller 2.1 and should run as x86 application on both x86 and x64 based systems.

## Requirements

No requirements if you use the compiled EXE. 

If you want to build it yourself:

- yara : It's recommended to use the most recent version of the compiled packages for Windows (x86) - Download it from here: http://goo.gl/PQjmsf
- scandir : faster alternative to os.walk()
- colorama : to color it up


## Usage

    usage: skeletonkey-scanner.py [-h] [-p path] [--printAll] [--noprocscan]
                                  [--nofilescan] [--dots] [--debug]

    SKELETONKEY Scanner

    optional arguments:
      -h, --help    show this help message and exit
      -p path       Path to scan
      --printAll    Print all files that are scanned
      --noprocscan  Skip the process scan
      --nofilescan  Skip the file scan
      --dots        Print a dot for every scanned file to see the progress
      --debug       Debug output

## Screenshots

![Screen](/screens/skelscan.png?raw=true)

## Notice

IOCs are based on the report by the Dell SecureWorks Counter Threat Unit(TM) (CTU) researchers. Scanner has not been tested on one of the samples. They have not been published as they contain campaign and customer strings.

## Contact

Profile on Company Homepage
http://www.bsk-consulting.de/author/froth/

Twitter
@MalwrSignatures

If you are interested in a corporate solution for APT scanning, check:
http://www.bsk-consulting.de/apt-scanner-thor/
