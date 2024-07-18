/**

A Frida script that disables Flutter's TLS verification

This script works on Android x86, Android x64 and iOS x64. It uses pattern matching to find [ssl_verify_peer_cert in handshake.cc](https://github.com/google/boringssl/blob/master/ssl/handshake.cc#L323)

If the script doesn't work, take a look at https://github.com/NVISOsecurity/disable-flutter-tls-verification#warning-what-if-this-script-doesnt-work 


*/

// Configuration object containing patterns to locate the ssl_verify_peer_cert function
// for different platforms and architectures.
var config = {
    "ios":{
        "modulename": "Flutter",
        "patterns":{
            "arm64": [
                "FF 83 01 D1 FA 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 FD 7B 05 A9 FD 43 01 91 F? 03 00 AA ?? 0? 40 F9 ?8 1? 40 F9 15 ?? 4? F9 B5 00 00 B4",
                "FF 43 01 D1 F8 5F 01 A9 F6 57 02 A9 F4 4F 03 A9 FD 7B 04 A9 FD 03 01 91 F3 03 00 AA 14 00 40 F9 88 1A 40 F9 15 E9 40 F9 B5 00 00 B4 B6 46 40 F9"

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
                "2D E9 F? 4? D0 F8 00 80 81 46 D8 F8 18 00 D0 F8",
            ],
            "x64": [
                "55 41 57 41 56 41 55 41 54 53 50 49 89 f? 4c 8b 37 49 8b 46 30 4c 8b a? ?? 0? 00 00 4d 85 e? 74 1? 4d 8b",
                "55 41 57 41 56 41 55 41 54 53 48 83 EC 18 49 89 FF 48 8B 1F 48 8B 43 30 4C 8B A0 28 02 00 00 4D 85 E4 74",
                "55 41 57 41 56 41 55 41 54 53 48 83 EC 38 C6 02 50 48 8B AF A? 00 00 00 48 85 ED 74 7? 48 83 7D 00 00 74"
            ]
        }
    }
};

// Flag to check if TLS validation has already been disabled
var TLSValidationDisabled = false;
var flutterLibraryFound = false;
var tries = 0;
var maxTries = 5;
var timeout = 1000;
disableTLSValidation();


// Main function to disable TLS validation for Flutter
function disableTLSValidation() {

    // Stop if ready
    if (TLSValidationDisabled) return;

    tries ++;
    if(tries > maxTries){
        console.log('[!] Max attempts reached, stopping');
        return;
    }
    
    console.log(`[+] Attempting to find and hook ssl_verify_peer_cert (${tries}/${maxTries})`)

    // Get reference to module. Necessary for iOS, and usefull check for Android
    var platformConfig = config[Java.available ? "android" : "ios"];
    var m = Process.findModuleByName(platformConfig["modulename"]);

    if (m === null) {
        console.log('[!] Flutter library not found');
        setTimeout(disableTLSValidation, timeout);
        return;
    }
    else{
        // reset counter so that searching for ssl_verify_peer_cert also gets x attempts
        if(flutterLibraryFound == false){
            flutterLibraryFound = true;
            tries = 1;
        }
    }

    if (Process.arch in platformConfig["patterns"])
    {
        var ranges;
        if(Java.available){
            // On Android, getting ranges from the loaded module is buggy, so we revert to Process.enumerateRanges
            ranges = Process.enumerateRanges({protection: 'r-x'}).filter(isFlutterRange)

        }else{
            // On iOS, there's no issue
            ranges = m.enumerateRanges('r-x')
        }

        findAndPatch(ranges, platformConfig["patterns"][Process.arch], Java.available && Process.arch == "arm" ? 1 : 0);
    }
    else
    {
        console.log('[!] Processor architecture not supported: ', Process.arch);
    }

    if (!TLSValidationDisabled)
    {        
        if(tries < maxTries){
            console.log(`[!] Flutter library found, but ssl_verify_peer_cert could not be found.`)
        }
        else
        {
            console.log('[!] ssl_verify_peer_cert not found. Please open an issue at https://github.com/NVISOsecurity/disable-flutter-tls-verification/issues');
        }
    }
}

// Find and patch the method in memory to disable TLS validation
function findAndPatch(ranges, patterns, thumb) {
   
    ranges.forEach(range => {
        patterns.forEach(pattern => {
            var matches = Memory.scanSync(range.base, range.size, pattern);
            matches.forEach(match => {
                var info = DebugSymbol.fromAddress(match.address)
                console.log(`[+] ssl_verify_peer_cert found at offset: ${info.name}`);
                TLSValidationDisabled = true;
                hook_ssl_verify_peer_cert(match.address.add(thumb));
                console.log('[+] ssl_verify_peer_cert has been patched')
    
            });
            if(matches.length > 1){
                console.log('[!] Multiple matches detected. This can have a negative impact and may crash the app. Please open a ticket')
            }
        });
        
    });
    
    // Try again. disableTLSValidation will not do anything if TLSValidationDisabled = true
    setTimeout(disableTLSValidation, timeout);
}

function isFlutterRange(range){
    var address = range.base
    var info = DebugSymbol.fromAddress(address)
    if(info.moduleName != null){
        if(info.moduleName.toLowerCase().includes("flutter")){
            return true;
        }
    }
    return false;
}

// Replace the target function's implementation to effectively disable the TLS check
function hook_ssl_verify_peer_cert(address) {
    Interceptor.replace(address, new NativeCallback((pathPtr, flags) => {
        return 0;
    }, 'int', ['pointer', 'int']));
}