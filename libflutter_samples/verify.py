config = {
    "ios":{
        "modulename": "Flutter",
        "patterns":{
            "arm64": [
                "FF 83 01 D1 FA 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 FD 7B 05 A9 FD 43 01 91 F? 03 00 AA ?? 0? 40 F9 ?8 1? 40 F9 15 ?? 4? F9 B5 00 00 B4",
            ],
        },
    },
    "android":{
        "modulename": "libflutter.so",
        "patterns":{
            "arm64": [
                "F? 0F 1C F8 F? 5? 01 A9 F? 5? 02 A9 F? ?? 03 A9 ?? ?? ?? ?? 68 1A 40 F9",
                "F? 43 01 D1 FE 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 13 00 40 F9 F4 03 00 AA 68 1A 40 F9",
                "FF 43 01 D1 FE 67 01 A9 ?? ?? 06 94 ?? 7? 06 94 68 1A 40 F9 15 15 41 F9 B5 00 00 B4 B6 4A 40 F9",
            ],
            "arm": [
                "2D E9 F? 4? D0 F8 00 80 81 46 D8 F8 18 00 D0 F8 ??",
            ],
            "x64": [
                "55 41 57 41 56 41 55 41 54 53 50 49 89 f? 4c 8b 37 49 8b 46 30 4c 8b a? ?? 0? 00 00 4d 85 e? 74 1? 4d 8b",
                "55 41 57 41 56 41 55 41 54 53 48 83 EC 18 49 89 FF 48 8B 1F 48 8B 43 30 4C 8B A0 28 02 00 00 4D 85 E4 74"
            ]
        }
    }
}

import os, glob, re, binascii

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


for file in list(glob.glob('./*/*/*')):                                       
    reader = open(file, mode='rb').read()
    hexstring = binascii.hexlify(reader)

    match = False

    if "ios" in file:
        patterns = config["ios"]["patterns"]["arm64"]
    elif "x64" in file:
        patterns = config["android"]["patterns"]["x64"]
    elif "arm64" in file:
        patterns = config["android"]["patterns"]["arm64"]
    elif "arm" in file:
        patterns = config["android"]["patterns"]["arm"]

    result = []
    for pattern in patterns:
        regex = re.compile(b'' + pattern.lower().replace(" ", "").replace("?", ".").encode('utf-8'))
        result = re.findall(regex, hexstring)
        if len(result) > 0:
            break

    if len(result) == 1:
        location = hex(hexstring.index(result[0]))
        print(f"{file} > {bcolors.OKGREEN} OK {bcolors.ENDC} [{location}] [{result[0].decode()}]")
    elif len(result) > 1:
            print(f"{file} > {bcolors.FAIL} {len(result)} results {bcolors.ENDC}")  
    else:
        print(f"{file} > {bcolors.FAIL} NOK {bcolors.ENDC}")


