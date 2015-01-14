# Skeleton Key Malware Scanner

Scanner for Skeleton Key Malware

Detection is based on four detection methods:

    1. File Name IOC 

    2. Yara Ruleset

    3. SHA1 hash check
       Compares known malicious SHA1 hashes with scanned files

    4. Process parameter check
       Detecting a PsExec.exe with NTLM Hash as parameter (as described in report)

All included IOCs are extracted from [this report](http://goo.gl/aAk3lN).

The Windows binary is compiled with PyInstaller 2.1 and should run as x86 application on both x86 and x64 based systems.

## Antivirus - False Positives

The compiled scanner is [falsely detected](https://www.virustotal.com/en/file/7f855a1e66339f00464abe89559b56c6a0559310761af4f22f7d567f8c461226/analysis/1421234417/) as a Virus by McAfee and some other second-class scanners. This may be caused by the fact that the scanner is a compiled python script that implement some file system and process scanning features that are also used in compiled malware code. 

If you don't trust the compiled executable, please compile it yourself. 

### Compile the Scanner

Download PyInstaller, switch to the pyinstaller program directory and execute:

    python ./pyinstaller.py -F C:\path\to\skeletonkey-scanner.py

This will create a "skeletonkey-scanner.exe" in the subfolder "./skeletonkey-scanner/dist".

### Pro Tip (optional)

To include the msvcr100.dll to improve the target os compatibility change the line in the file "./skeletonkey-scanner/skeletonkey-scanner.spec" that contains `a.bianries,` to the following:

    a.binaries + [('msvcr100.dll', 'C:\Windows\System32\msvcr100.dll', 'BINARY')],

## Requirements

No requirements if you use the compiled EXE. 

If you want to build it yourself:

- [yara](http://goo.gl/PQjmsf) : It's recommended to use the most recent version of the compiled packages for Windows (x86) - Download it from here: http://goo.gl/PQjmsf
- [scandir](https://github.com/benhoyt/scandir) : faster alternative to os.walk()
- [colorama](https://pypi.python.org/pypi/colorama) : to color it up

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
