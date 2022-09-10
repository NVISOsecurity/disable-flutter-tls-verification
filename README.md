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

Before creating a GitHub issue, please test the following steps:

* Can you intercept HTTP requests from the demo application?
    * If not, note that Flutter apps do not use the system's proxy settings by default. This means you should use [Proxydroid on Android](https://blog.nviso.eu/2019/08/13/intercepting-traffic-from-android-flutter-applications/) and [OpenVPN on iOS](https://blog.nviso.eu/2020/06/12/intercepting-flutter-traffic-on-ios/) (or a rogue rogue access point on both). On the Android Studio AVDs, you can use `-http-proxy` when launching the emulator.
* Can you intercept HTTPS requests from the demo application?
* Have you checked if your app's flutter library is inside the libflutter_samples directory?
    * For Android: run `apktool d <YOURAPK>` and run `md5sum` on `libs/<ARCH>/libflutter.so`
    * For iOS: Extract an *unencrypted* IPA, unzip it and run `md5sum` on `Payload/Runner.app/Frameworks/Flutter.framework/Flutter`
    * Alternatively, copy `libflutter.so` or `Flutter` to the correct folder in `libflutter_samples` and run `python3 verify.py`

If you can succesfully intercept all requests from the demo app and your library is not included in the samples, please [open a GitHub issue](https://github.com/NVISOsecurity/disable-flutter-tls-verification/issues) with the app in question. It is possible that the app is using additional SSL pinning plugins, so a combination of this plugin and objection / other Frida scripts may be necessary. This is outside of the scope of this project and you will have to RE yourself to identify additional pinning protections.

