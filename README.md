# disable-flutter-tls-verification
A Frida script that disables Flutter's TLS verification

This script works on Android x86, Android x64 and iOS x64. It uses pattern matching to find [ssl_verify_peer_cert in handshake.cc](https://github.com/google/boringssl/blob/master/ssl/handshake.cc#L323)

You can use it via Frida by downloading disable-flutter-tls.js or by using Frida codeshare:

```bash
frida -U -f your.package.name -l disable-flutter-tls.js --no-pause

# or Frida codeshare

frida -U --codeshare TheDauntless/disable-flutter-tls-v1 -f YOUR_BINARY
```

Further information can be found in [this blogpost](https://blog.nviso.eu/2022/08/18/intercept-flutter-traffic-on-ios-and-android-http-https-dio-pinning/).

## :warning: What if this script doesn't work?

It is possible that TLS verification still fails with this script. There are a few possibilities:

* It is using normal TLS verification and the patterns don't match. If this is the case, please [open a GitHub issue](https://github.com/NVISOsecurity/disable-flutter-tls-verification/issues) with the app in question
* It is using some weird SSL pinning plugin which actually performs the pinning on the native iOS / Android side. In this case, manual RE'ing and hooking is required

In all cases, note that Flutter apps do not use the system's proxy settings by default. This means you should use [Proxydroid on Android](https://blog.nviso.eu/2019/08/13/intercepting-traffic-from-android-flutter-applications/) and [OpenVPN on iOS](https://blog.nviso.eu/2020/06/12/intercepting-flutter-traffic-on-ios/) (or a rogue rogue access point on both).