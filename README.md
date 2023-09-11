- [Description](#description)
- [Installation](#installation)
- [Profile method for macOS host](#profile-method-for-macos-host)
  * [Howto](#howto)
- [Profile method for non-jailbroken devices](#profile-method-for-non-jailbroken-devices)
  * [Howto](#howto-1)
- [Secret preference method for jailbroken devices](#secret-preference-method-for-jailbroken-devices)
  * [Howto](#howto-2)
- [Enable HTTP instrumentation method](#enable-http-instrumentation-method)

# Description

Simple pure python utility for sniffing HTTP/HTTPS decrypted traffic recorded by one of Apple's not-so-well documented
APIs.

# Installation

```shell
python3 -m pip install -U harlogger
```

# Profile method for macOS host

This method applies to Apple's CFNetwork profile. This profile is meant for debugging processes using the CFNetwork
framework. **This method doesn't include the request/response body.**

## Howto

- Download Apple's CFNetwork profile which can be found here:
  https://developer.apple.com/services-account/download?path=/iOS/iOS_Logs/NetworkDiagnostic.mobileconfig

- Install it using double-click

- That's it! :) You can now just start sniffing out everything using:
    ```shell
    python3 -m harlogger profile
    ```

# Profile method for non-jailbroken devices

This method applies to Apple's CFNetwork profile. This profile is meant for debugging processes using the CFNetwork
framework. **This method doesn't include the request/response body.**

## Howto

- Download Apple's CFNetwork profile which can be found here:
  https://developer.apple.com/services-account/download?path=/iOS/iOS_Logs/CFNetworkDiagnostics.mobileconfig

- Install it via any way you prefer. I'm using [`pymobiledevice3`](https://github.com/doronz88/pymobiledevice3):

    ```shell
    # if you don't already have it
    python3 -m pip install -U pymobiledevice3
    
    # install the profile
    pymobiledevice3 profile install CFNetworkDiagnostics.mobileconfig
    ```

- That's it! :) You can now just start sniffing out everything using:
    ```shell
    python3 -m harlogger mobile profile
    ```

Output should look like:

```
➜  harlogger git:(master) ✗ python3 -m harlogger profile
➡️️   POST https://www.bing.com/fd/ls/lsp.aspx HTTP/1.1
Accept: */*
Content-Type: text/xml
Origin: https://www.bing.com
Accept-Encoding: gzip, deflate, br
Cookie: SRCHHPGUSR=CW=414&CH=622&SW=414&SH=736&DPR=3&UTC=180&DM=1&SRCHLANG=en&HV=1634801804; _HPVN=CS=eyJQbiI6eyJDbiI6MiwiU3QiOjAsIlFzIjowLCJQcm9kIjoiUCJ9LCJTYyI6eyJDbiI6MiwiU3QiOjAsIlFzIjowLCJQcm9kIjoiSCJ9LCJReiI6eyJDbiI6MiwiU3QiOjAsIlFzIjowLCJQcm9kIjoiVCJ9LCJBcCI6dHJ1ZSwiTXV0ZSI6dHJ1ZSwiTGFkIjoiMjAyMS0xMC0yMVQwMDowMDowMFoiLCJJb3RkIjowLCJEZnQiOm51bGwsIk12cyI6MCwiRmx0IjowLCJJbXAiOjEwfQ==; SUID=M; _EDGE_S=SID=1BF42681120765EF1EA73656137A640E; _SS=SID=1BF42681120765EF1EA73656137A640E; MUID=1B0D347B85756FDD055524B284086E36; SRCHD=AF=NOFORM; SRCHUID=V=2&GUID=5B989717430E450D9314C927C97602C9&dmnchg=1; SRCHUSR=DOB=20211007; _EDGE_V=1; MUIDB=1B0D347B85756FDD055524B284086E36
User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 14_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1 Mobile/15E148 Safari/604.1
Referer: https://www.bing.com/
Content-Length: 458
Accept-Language: en-us

⬅️   HTTP/2.0 204 (request POST https://www.bing.com/fd/ls/lsp.aspx HTTP/1.1)
x-msedge-ref: Ref A: E5B5AE34FBA148E6BDFFBF421B940462 Ref B: VIEEDGE1816 Ref C: 2021-10-21T07:36:44Z
Date: Thu, 21 Oct 2021 07:36:44 GMT
x-cache: CONFIG_NOCACHE
Access-Control-Allow-Origin: *
```

# Secret preference method for jailbroken devices

iOS 14.x devices contain a hidden feature for sniffing decrypted HTTP/HTTPS traffic from all processes using the
CFNetwork framework into an [HAR](https://en.wikipedia.org/wiki/HAR_(file_format).)
format. To trigger this feature on a jailbroken device, you can simply place the correct configuration
for `com.apple.CFNetwork` and trigger the `com.apple.CFNetwork.har-capture-update` notification.
**This method includes the request/response body as well.**

**iOS 13.x or under don't have this feature.**

## Howto

- Put [com.apple.CFNetowrk.plist](./com.apple.CFNetwork.plist) inside `/var/mobile/Library/Preferences/`
- Restart the device
- That's it! :) You can now just start sniffing out everything using:
    ```shell
    python3 -m harlogger preference
    ```

Output should look like:

```
➜  harlogger git:(master) ✗ python3 -m harlogger mobile preference
➡️   CFNetwork(1140) POST https://www.bing.com/fd/ls/lsp.aspx
POST /fd/ls/lsp.aspx HTTP/2.0
Accept: */*
Content-Type: text/plain
Origin: https://www.bing.com
Cache-Control: max-age=0
Content-Length: 472
Accept-Language: en-us
User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 14_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1 Mobile/15E148 Safari/604.1
Accept-Encoding: gzip, deflate, br
Referer: https://www.bing.com/

⬅️   CFNetwork(1140) 0
➡️   CFNetwork(1140) POST https://www.bing.com/fd/ls/lsp.aspx
POST /fd/ls/lsp.aspx HTTP/2.0
Accept: */*
Content-Type: text/xml
Origin: https://www.bing.com
Content-Length: 378
Accept-Language: en-us
Host: www.bing.com
User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 14_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1 Mobile/15E148 Safari/604.1
Referer: https://www.bing.com/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

<ClientInstRequest><Events><E><T>Event.ClientInst</T><IG>EB94C422BC394F90A876D39A790BECBC</IG><TS>1634801882467</TS><D><![CDATA[[{"T":"CI.BoxModel","FID":"CI","Name":"v2.8","SV":"4","P":{"C":1,"N":5,"I":"5iv","S":"V","M":"V+L+M+MT+E+N+C+K+BD","T":1669960,"F":0},"V":"zrpx/////////visible/+zryw/////////hidden/@p"}]]]></D></E></Events><STS>1634801882467</STS></ClientInstRequest>
```

# Enable HTTP instrumentation method

Starting at iOS 15.0, the device will require the target process to have any of the following requirements:

- `com.apple.private.cfnetwork.har-capture-delegation` entitlement
- `get-task-allow` entitlement
- `com.apple.security.get-task-allow` entitlement
- OS build to be in `debug` mode

In order to make the device enable HAR logging you may
use [`pymobiledevice3`](https://github.com/doronz88/pymobiledevice3) as follows:

```shell
python3 -m pymobiledevice3 developer dvt har
```

Now you can start sniffing using the preference method:

 ```shell
python3 -m harlogger preference
```
