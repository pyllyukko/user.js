# user.js

**Firefox configuration hardening**

A [user.js][1] configuration file for Mozilla Firefox designed to harden Firefox settings and
make it more secure.

[![Build Status](https://travis-ci.org/pyllyukko/user.js.svg?branch=master)](https://travis-ci.org/pyllyukko/user.js)

### Main goals

* Limit the possibilities to track the user through [web analytics](https://en.wikipedia.org/wiki/Web_analytics).
* Harden the browser against known data disclosure or code execution vulnerabilities.
* Limit the browser from storing anything even remotely sensitive persistently
* Make sure the browser doesn't reveal too much information to [shoulder surfers](https://en.wikipedia.org/wiki/Shoulder_surfing_%28computer_security%29)
* Harden the browser's encryption (cipher suites, protocols, trusted CAs)
* Hopefully limit the attack surface by disabling various features
* Still be usable in daily use

### How to achieve this?

There are several parts to all this and they are:

* Using the user.js settings file itself
* Running a selected list of browser extensions
* Maintaining good security practices
* Using the **cas.sh** script to limit the CAs

----------------------------------------------

TODO insert toc

## Download

Different download methods are available:

 * Clone using git: `git clone https://github.com/pyllyukko/user.js`
 * Download and extract the [ZIP file](https://github.com/pyllyukko/user.js/archive/master.zip) containing the latest version.
 * Download the latest `user.js` [directly](https://raw.githubusercontent.com/pyllyukko/user.js/master/user.js)

## Installation

### Single profile installation

Copy `user.js` in your current user profile directory, or (recommended) to a fresh, newly
created Firefox profile directory.

The file should be located at:

| OS                         | Path                                                                                                                                          |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Windows 7                  | `%APPDATA%\Mozilla\Firefox\Profiles\XXXXXXXX.your_profile_name\user.js`                                                                       |
| Linux                      | `~/.mozilla/firefox/XXXXXXXX.your_profile_name/user.js`                                                                                       |
| OS X                       | `~/Library/Application Support/Firefox/Profiles/XXXXXXXX.your_profile_name`                                                                   |
| Android                    | `/data/data/org.mozilla.firefox/files/mozilla/XXXXXXXX.your_profile_name` and see [issue #14](https://github.com/pyllyukko/user.js/issues/14) |
| Sailfish OS + Alien Dalvik | `/opt/alien/data/data/org.mozilla.firefox/files/mozilla/XXXXXXXX.your_profile_name`                                                           |
| Windows (portable)         | `[firefox directory]\Data\profile\`                                       |

Do note that these settings alter your browser behaviour quite a bit, so it is recommended to
either create a completely new [profile][15] for Firefox or backup your existing 
[profile directory](http://kb.mozillazine.org/Profile_folder_-_Firefox) before putting the
```user.js``` file in place.

To enable the Profile Manager, run Firefox with
[command-line arguments](http://kb.mozillazine.org/Command_line_arguments):
`firefox --no-remote -P`

### System-wide installation

Create `local-settings.js` in Firefox installation directory, with the following contents:

```
pref("general.config.obscure_value", 0);
pref("general.config.filename", "mozilla.cfg");
```

This file should be located at:

| OS      | Path                                                         |
| ------- | ------------------------------------------------------------ |
| Windows | `C:\Program Files (x86)\Mozilla Firefox\default\pref\`       |
| Linux   |**This file is not required**                                 |
| OS X    | `/Applications/Firefox.app/Contents/Resources/defaults/pref` |


In `user.js`, Change `user_pref(` to  one of:
 * `pref(` (the value will be used as default value on Firefox profile creation, it can be changed in `about:config`)
 * `lockPref(` (the value will be used as default value on Firefox profile creation, will be locked and can't be changed) in `user.js` or in Firefox's `about:config` or settings.

Copy `user.js` to the Firefox installation directory. The file should be located at:

| OS             | Path                                                       |
| -------------- | ---------------------------------------------------------- |
| Windows        | `C:\Program Files (x86)\Mozilla Firefox\mozilla.cfg`       |
| Linux          | `/etc/firefox/firefox.js`                                  |
| Linux (Debian) | `/etc/firefox-esr/firefox-esr.js`                          |
| OS X           | `/Applications/Firefox.app/Contents/Resources/mozilla.cfg` |

### Updating using git

For any of the above methods, you can keep your browser's `user.js` with the latest version available here: Clone the repository, and create a symbolic link from the appropriate location to the `user.js` file in the repository. Just run `git pull` in the repository when you want to update, then restart Firefox:

````
cd ~/.mozilla/firefox
git clone 'https://github.com/pyllyukko/user.js.git'
cd XXXXXXXX.your_profile_name
ln -s ../user.js/user.js user.js
````

### Verifying

Verify that the settings are effective from [about:support](http://kb.mozillazine.org/Troubleshooting_Information_report#Modified_Preferences) (check the "Important Modified Preferences" and "user.js Preferences" sections).

--------------------------------------------

What does it do?
----------------

There's a whole lot of settings that this modifies and they are divided in the following sections or categories:

* HTML5 / [APIs](https://wiki.mozilla.org/WebAPI) / DOM
* Miscellaneous
* Extensions / plugins related
* Firefox (anti-)[features](https://en.wikipedia.org/wiki/Feature_creep) / components
* [Automatic connections](https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections)
* HTTP protocol related
* Caching
* UI related
* TLS / HTTPS / OCSP related
* Cipher suites

Some of the settings in this [user.js][1] file might seem redundant, as some of them are
already set to the same values by default. However, the [user.js][1] file has this nice
property, that even if you go change any of these settings through [about:config][6], they're
reset to the [user.js][1] defined values after you restart Firefox. So [user.js][1] makes
sure they're back at the secure default values always when you start your browser. That way,
it also makes experimenting with different settings easier.

Here are some of the "highlights" from each category. For a full list of settings and 
references, check the ```user.js``` file itself.


### HTML5 / APIs / DOM

* Disable [geolocation](https://www.mozilla.org/en-US/firefox/geolocation/)
* Don't reveal internal [IP addresses](http://net.ipcalf.com/) ([media.peerconnection.enabled](https://blog.mozilla.org/futurereleases/2013/01/12/capture-local-camera-and-microphone-streams-with-getusermedia-now-enabled-in-firefox/))
  * [BeEF Module: Get Internal IP WebRTC](https://github.com/beefproject/beef/wiki/Module%3A-Get-Internal-IP-WebRTC)
* [browser.send_pings](http://kb.mozillazine.org/Browser.send_pings)
* Disable [WebGL](https://en.wikipedia.org/wiki/WebGL)
* Disable [Battery API](http://mashable.com/2015/08/04/battery-privacy-html5/)

### Miscellaneous

* Enables Firefox's [mixed content blocking](https://blog.mozilla.org/tanvi/2013/04/10/mixed-content-blocking-enabled-in-firefox-23/) (also for "display" content)
* Disables various your-browser-knows-better-let-me-guess-what-you-were-trying features
  * Disable this [keyword thingie](http://kb.mozillazine.org/Keyword.enabled)
  * Disable [Domain Guessing](http://www-archive.mozilla.org/docs/end-user/domain-guessing.html)

### Extensions / plugins related

It is common for [client side attacks](https://www.offensive-security.com/metasploit-unleashed/client-side-attacks/) to target [browser extensions](https://www.mozilla.org/en-US/plugincheck/), instead of the browser itself (just look at all those [Java](https://en.wikipedia.org/wiki/Criticism_of_Java#Security) and [Flash](https://www.cvedetails.com/vulnerability-list/vendor_id-53/product_id-6761/Adobe-Flash-Player.html) vulnerabilities). Make sure your extensions and plugins are always up-to-date.

* Disable Adobe Flash
* Enable [click to play](https://wiki.mozilla.org/Firefox/Click_To_Play)
* Enable [add-on updates](https://blog.mozilla.org/addons/how-to-turn-off-add-on-updates/)

### Firefox features

* Enables Firefox's built-in [tracking protection][12]
* Disables [telemetry](https://wiki.mozilla.org/Telemetry), [Crash Reporter](https://support.mozilla.org/en-US/kb/Mozilla%20Crash%20Reporter), [healt report](https://support.mozilla.org/en-US/kb/firefox-health-report-understand-your-browser-perf), [heartbeat](https://wiki.mozilla.org/Advocacy/heartbeat) and other such privacy invading nonsense

### Automatic connections

This section disables some of Firefox's [automatic connections](https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections).

* Disables prefetching
  * [network.prefetch-next](http://kb.mozillazine.org/Network.prefetch-next)
  * [network.dns.disablePrefetch](http://kb.mozillazine.org/Network.dns.disablePrefetch)
* Disable [Necko](https://wiki.mozilla.org/Privacy/Reviews/Necko)/predictor
* Disable [search suggestions](http://kb.mozillazine.org/Browser.search.suggest.enabled)

Do note, that some automatic connections are still intentionally left out (as in not disabled), namely the following:

* [browser.safebrowsing.malware.enabled](http://kb.mozillazine.org/Browser.safebrowsing.malware.enabled)
* [plugins.update.notifyUser](https://wiki.mozilla.org/Firefox3.6/Plugin_Update_Awareness_Security_Review)
* ```extensions.update.enabled```
* [extensions.blocklist.enabled](http://kb.mozillazine.org/Extensions.blocklist.enabled)

See also [#20](https://github.com/pyllyukko/user.js/issues/20).

### HTTP

* Referer header:
  * Spoofs the referer header with [network.http.referer.spoofSource][9] (see: [#2](https://github.com/pyllyukko/user.js/pull/2))
  * "[Don't send the Referer header when navigating from a https site to another https site.](http://kb.mozillazine.org/Network.http.sendSecureXSiteReferrer#false)"
* Don't accept [3rd party cookies](http://kb.mozillazine.org/Network.cookie.cookieBehavior#1)

### Caching

* Permanently enables [private browsing][8] mode
* Prevents Firefox from storing data filled in web page forms
* Disables [password manager](https://support.mozilla.org/en-US/kb/Remembering+passwords)

### UI related

* Don't [suggest any URLs](http://kb.mozillazine.org/Browser.urlbar.maxRichResults) while typing at the address bar

### TLS / HTTPS / OCSP related

* TLS 1.[0-3] only
* Require [OCSP](https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol)
  * Notice that this setting has some [privacy implications](https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol#Privacy_concerns)
* [OCSP stapling](https://blog.mozilla.org/security/2013/07/29/ocsp-stapling-in-firefox/) (enabled by default anyway)
* Disable [TLS session tickets](https://www.blackhat.com/us-13/archives.html#NextGen)
* Enforces [pinning](https://wiki.mozilla.org/SecurityEngineering/Public_Key_Pinning)

### Ciphers

This section tweaks the cipher suites used by Firefox. The idea is to support only the strongest ones with emphasis on [forward secrecy](https://en.wikipedia.org/wiki/Forward_secrecy), but without compromising compatibility with all those sites on the internet. As new crypto related flaws are discovered quite often, the cipher suites can be [tweaked to mitigate these newly discovered threats](https://github.com/pyllyukko/user.js/pull/18).

Here's a list of the ciphers with default config and Firefox 38.8.0 ESR:

```
Cipher Suites (11 suites)
    Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)
    Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)
    Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a)
    Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009)
    Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)
    Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)
    Cipher Suite: TLS_DHE_RSA_WITH_AES_128_CBC_SHA (0x0033)
    Cipher Suite: TLS_DHE_RSA_WITH_AES_256_CBC_SHA (0x0039)
    Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
    Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)
    Cipher Suite: TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000a)
```

Here's the list with this config:

```
Cipher Suites (6 suites)
    Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)
    Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)
    Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a)
    Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)
    Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
    Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)
```

This is not enough!
-------------------

Here's some other tips how you can further harden Firefox:

* Keep your browser updated! If you check [Firefox's security advisories](https://www.mozilla.org/security/known-vulnerabilities/firefox.html), you'll see that pretty much every new version of Firefox contains some security updates. If you don't keep your browser updated, you've already lost the game.
* Disable/uninstall all unnecessary extensions and plugins!
* If a plugin is absolutely required, [check for plugin updates](https://www.mozilla.org/en-US/plugincheck/)
* Create different [profiles][15] for different purposes
* Change the Firefox's built-in tracking protection to use the [strict list](https://support.mozilla.org/en-US/kb/tracking-protection-pbm?as=u#w_change-your-block-list)
* Change the timezone for Firefox by using the ```TZ``` environment variable (see [here](https://wiki.archlinux.org/index.php/Firefox_privacy#Change_browser_time_zone)) to reduce it's value in browser fingerprinting
* Completely block unencrypted communications using the `HTTPS Everywhere` toolbar button > `Block all unencrypted requests`. This will break websites where HTTPS is not available.

### Add-ons

Here is a list of the most essential security and privacy enhancing add-ons that you should consider using:

* [Certificate Patrol][4]
  * I recommend setting the 'Store certificates even when in [Private Browsing][8] Mode' to get full benefit out of certpatrol, even though it stores information about the sites you visit
* [HTTPS Everywhere](https://www.eff.org/https-everywhere) and [HTTPS by default](https://addons.mozilla.org/firefox/addon/https-by-default/)
* [NoScript](https://noscript.net/)
* [DuckDuckGo Plus](https://addons.mozilla.org/firefox/addon/duckduckgo-for-firefox/) (instead of Google)
* [No Resource URI Leak](https://addons.mozilla.org/firefox/addon/no-resource-uri-leak/) (see [#163](https://github.com/pyllyukko/user.js/issues/163))
* [Decentraleyes](https://addons.mozilla.org/firefox/addon/decentraleyes/)
* [Canvas Blocker](https://addons.mozilla.org/firefox/addon/canvasblocker/) ([Source code](https://github.com/kkapsner/CanvasBlocker))

#### Tracking protection

Tracking protection is one of the most important technologies that you need. The usual recommendation has been to run the [Ghostery](https://www.ghostery.com/) extension, but as it is made by a [potentially evim(tm) advertising company](https://en.wikipedia.org/wiki/Ghostery#Criticism), some people feel that is not to be trusted. One notable alternative is to use [uBlock](https://github.com/gorhill/uBlock), which can also be found at [Mozilla AMO](https://addons.mozilla.org/firefox/addon/ublock-origin/).

Ghostery is still viable option, but be sure to disable the [GhostRank](https://www.ghostery.com/en/faq#q5-general) feature.

Do note, that this user.js also enables Mozilla's built-in [tracking protection][12], but as that's quite new feature it is to be considered only as a fallback and not a complete solution. As it utilizes [Disconnect's list](https://support.mozilla.org/en-US/kb/tracking-protection-firefox#w_what-is-tracking-protection), recommending Disconnect seems redundant.

So to summarize, pick one between Ghostery and uBlock, depending on your personal preferences.

See also:
* [Mozilla Lightbeam][13] extension
* [Privacy Badger](https://www.eff.org/privacybadger) extension from EFF (also to be considered as an additional security measure and not a complete solution)
* [Web Browser Addons](https://prism-break.org/en/subcategories/gnu-linux-web-browser-addons/) section in [PRISM break](https://prism-break.org/)
* [\[Talk\] Ghostery Vs. Disconnect.me Vs. uBlock #16](https://github.com/pyllyukko/user.js/issues/16)
* [Ghostery sneaks in new promotional messaging system #47](https://github.com/pyllyukko/user.js/issues/47)
* [Are We Private Yet?](https://web.archive.org/web/20150801031411/http://www.areweprivateyet.com/) site (made by Ghostery, archived)
* [Tracking Protection in Firefox For Privacy and Performance](https://kontaxis.github.io/trackingprotectionfirefox/#papers) paper
* [How Tracking Protection works in Firefox](https://feeding.cloud.geek.nz/posts/how-tracking-protection-works-in-firefox/)

#### Add-ons for mobile platforms

* [NoScript Anywhere](https://noscript.net/nsa/)
* [uBlock](https://addons.mozilla.org/android/addon/ublock-origin/)
* [HTTPS Everywhere](https://www.eff.org/https-everywhere)

## Online tests

#### Version checks

* **[Mozilla Plugin Check](https://www.mozilla.org/en-US/plugincheck/)**
* [Adobe Flash Player Version Check](https://www.adobe.com/software/flash/about/)
* [Java Version Check](https://www.java.com/en/download/installed.jsp)

#### Fingerprinting tests

* [BrowserSpy.dk](http://browserspy.dk/)
* [BrowserLeaks.com](https://www.browserleaks.com/firefox)
* [IP Check](http://ip-check.info/?lang=en)
* [Panopticlick](https://panopticlick.eff.org/)
* [Unique Machine](http://www.uniquemachine.org/)
* [Firefox Addon Detector](https://thehackerblog.com/addon_scanner/) [[1](https://thehackerblog.com/dirty-browser-enumeration-tricks-using-chrome-and-about-to-detect-firefox-plugins/)]
* [AudioContext Fingerprint Test Page](https://audiofingerprint.openwpm.com/)
* [Evercookie](https://samy.pl/evercookie/)
* [WebRTC Test Landing Page](https://mozilla.github.io/webrtc-landing/)
* [Onion test for CORS and WebSocket](https://cure53.de/leak/onion.php)
* [Official WebGL check](https://get.webgl.org/)
* [Battery API](https://robnyman.github.io/battery/) [[1](https://pstadler.sh/battery.js/)]
* [AmIUnique](https://amiunique.org/) ([1](https://github.com/DIVERSIFY-project/amiunique))

#### SSL tests

* [SSL Client Test](https://www.ssllabs.com/ssltest/viewMyClient.html)
* [How's My SSL](https://www.howsmyssl.com/)
* [Mixed content tests (Mozilla)](https://people.mozilla.org/~tvyas/mixedcontent.html) 
* [Mixed content tests (Microsoft)](https://ie.microsoft.com/testdrive/browser/mixedcontent/assets/woodgrove.htm) 
* [SSL Checker | Symantec CryptoReport](https://cryptoreport.websecurity.symantec.com/checker/views/sslCheck.jsp) 


#### Other tests

* [Test page for Firefox's built-in Tracking Protection](https://itisatrap.org/firefox/its-a-tracker.html)
* [Test page for Firefox's built-in Phishing Protection](https://itisatrap.org/firefox/its-a-trap.html) ("Web forgeries")
* [Test page for Firefox's built-in Malware Protection](https://itisatrap.org/firefox/its-an-attack.html) (attack page)
* [Test page for Firefox's built-in Malware Protection](https://itisatrap.org/firefox/unwanted.html) (unwanted software)
* [HTML5test](https://html5test.com/) - Comparison of supported HTML5 features in various browsers/versions
* [Filldisk](http://www.filldisk.com/)


## Known problems

There are plenty! Hardening your browser will break your interwebs. Here's some examples:

* If you get "TypeError: localStorage is null", you probably need to enable [local storage][3] (``dom.storage.enabled == true``)
* If you get "sec\_error\_ocsp\_invalid\_signing\_cert", it probably means that you don't have the required CA
* If you get "ssl\_error\_unsafe\_negotiation", it means the server is vulnerable to [CVE-2009-3555](https://www.cvedetails.com/cve/CVE-2009-3555) and you need to disable [security.ssl.require\_safe\_negotiation][2] (not enabled currently)
* If you set browser.frames.enabled to false, probably a whole bunch of websites will break
* Some sites require the [referer](https://en.wikipedia.org/wiki/HTTP_referer) header (usually setting ``network.http.sendRefererHeader == 2`` is enough to overcome this and the referer is still "[spoofed][9]")
* The [IndexedDB](https://en.wikipedia.org/wiki/Indexed_Database_API) is something that could potentially be used to track users, but it is also required by some browser add-ons in recent versions of Firefox. It would be best to disable this feature just to be on the safe side, but it is currently enabled, so that add-ons would work. See the following links for further info:
  * [Issue #8](https://github.com/pyllyukko/user.js/issues/8)
  * [IndexedDB Security Review](https://wiki.mozilla.org/Security/Reviews/Firefox4/IndexedDB_Security_Review) (this document also states that "IndexedDB is completely disabled in private browsing mode.", but this should still be verified)
  * [This discussion](http://forums.mozillazine.org/viewtopic.php?p=13842047&sid=041e5edcae225759b7cfffd43fc518d0#p13842047) on mozillaZine Forums
  * [IndexedDB page at MDN](https://developer.mozilla.org/en-US/docs/IndexedDB)
* [Firefox Hello](https://www.mozilla.org/en-US/firefox/hello/) requires [WebRTC](https://en.wikipedia.org/wiki/WebRTC), so you'll need to enable ```media.peerconnection.enabled``` & ```media.getusermedia.screensharing.enabled``` [and apparently](https://github.com/pyllyukko/user.js/issues/9#issuecomment-94526204) disable ```security.OCSP.require```.
* [Captive portals](https://en.wikipedia.org/wiki/Captive_portal) might not let OCSP requests through before authentication, so setting ```security.OCSP.require == false``` might be required before internet access is granted
* [DNT](https://en.wikipedia.org/wiki/Do_Not_Track) is not set, so you need to enable it manually if you want (see the discussion in [issue #11](https://github.com/pyllyukko/user.js/issues/11))
* The ```network.http.referer.spoofSource``` and ```network.http.sendRefererHeader``` settings seems to break the visualization of the 3rd party sites on the [Lightbeam][13] extension
* You can not view or inspect cookies when in private browsing (see https://bugzil.la/823941)
* Installation of ```user.js``` causes saved passwords to be removed from the Firefox (see [#27](https://github.com/pyllyukko/user.js/issues/27))
* Some payment gateways require third-party cookies to be fully enabled before you can make purchases on sites that use them (`network.cookie.cookieBehavior == 0`). Enabling `network.cookie.thirdparty.sessionOnly` will limit their lifetime to the length of the session no matter what.
* On some Android devices, all the pages might be blank (as seen [here](https://github.com/pyllyukko/user.js/pull/136#issuecomment-206812337)) if the setting ```layers.acceleration.disabled``` is set to ```true```. For more information, see [#136](https://github.com/pyllyukko/user.js/pull/136).

The [web console](https://developer.mozilla.org/en-US/docs/Tools/Web_Console) is your friend, **when** websites start to break.

CAs
---

It all started when I read [this blog post][5]...

So another part of my browser hardening was to somehow reduce the number of CAs trusted by my browser. First I thought I would sniff all the HTTPS connections and extract the certificates from there, to get the list of CAs I **really** need.

Then I came up with an better idea. I'd use [certpatrol][4] to record the certs from the HTTPS sites I visit. There was just one problem, certpatrol only stores the fingerprint of the issuer cert, which is usually a [intermediate CA](https://en.wikipedia.org/wiki/Intermediate_certificate_authorities). So I needed to get the root CA of the intermediate CA. The solution for this to use Firefox's *cert8.db* to extract the intermediate CAs and get the issuer (root CA) from there.

So I wrapped up a script that uses the certpatrol's SQLite DB and Mozilla's [certutil](https://developer.mozilla.org/en-US/docs/NSS_security_tools/certutil) to establish a list of required root CAs from the HTTPS sites that you have visited.

There's also a ready made list built in into the script, that has 28 root CAs in it. With this list of CAs you should already be able to browse the web quite freely. Of course there might also be some geographical variations as to what CAs "are required" for normal use.

This script requires that you have the CA certificates in ```/usr/share/ca-certificates/mozilla``` (see <https://packages.debian.org/search?keywords=ca-certificates>). Red Hat based systems have a different model for this, so the script doesn't currently work on those (see [#140](https://github.com/pyllyukko/user.js/issues/140)).

### Examples

**Do note**, that in order for all this to work, you **MUST** remove or rename Firefox's default CA list that is stored inside ```libnssckbi.so``` as described [here][5].

#### Check the current list of CAs in cert8.db

````
cas.sh -P ~/.mozilla/firefox/XXXXXXXX.current_profile -r
````

#### Import CAs

First check which CAs would be imported (dry-run):

````
cas.sh -p ~/.mozilla/firefox/XXXXXXXX.reference_profile -A
````

Then import the required CAs to new profile:

````
cas.sh -p  ~/.mozilla/firefox/XXXXXXXX.reference_profile -P ~/.mozilla/firefox/XXXXXXXX.new_profile -a
````

#### Verify that it worked

After you have run the script, verify from Firefox's [certificate settings](https://support.mozilla.org/en-US/kb/advanced-settings-browsing-network-updates-encryption?redirectlocale=en-US&redirectslug=Options+window+-+Advanced+panel#w_certificates-tab), that the list is indeed limited:

![Firefox certificates](./screenshots/firefox_certificate_settings-1.png)

### The default list

This is the default CA list, that you can use. It should be enough for basic use for the most biggest/popular sites. Of course this still depends on where you are located and what sites/services/etc. you use. If you know some popular site, that is not accessible with this root CA list, please let me know and I'll consider adding it to the list.

| Root CA							| Used by			|
| ------------------------------------------------------------- | ----------------------------- |
| AddTrust External CA Root					| https://www.debian.org/	|
| Baltimore CyberTrust Root					|				|
| COMODO Certification Authority				|				|
| Deutsche Telekom Root CA 2					|				|
| DigiCert High Assurance EV Root CA				| https://www.facebook.com/	|
| DigiCert Global Root CA					| https://duckduckgo.com/	|
| Entrust.net Secure Server Certification Authority		|				|
| Entrust.net Certification Authority (2048)			|				|
| [Entrust Root Certification Authority][11]                    | https://www.ssllabs.com/      |
| Equifax Secure Certificate Authority				|				|
| GTE CyberTrust Global Root					|				|
| GeoTrust Global CA						| https://www.google.com/	|
| GeoTrust Primary Certification Authority			| https://www.robtex.com/	|
| GeoTrust Primary Certification Authority - G3			|				|
| GlobalSign Root CA						| https://www.wikipedia.org/	|
| Go Daddy Class 2 Certification Authority			|				|
| Go Daddy Root Certificate Authority - G2			|				|
| Starfield Class 2 Certification Authority			| https://tools.ietf.org/	|
| StartCom Certification Authority				|				|
| UTN-USERFirst-Hardware					|				|
| ValiCert Class 2 Policy Validation Authority			|				|
| VeriSign Class 3 Public Primary Certification Authority - G3	| https://www.mysql.com/	|
| VeriSign Class 3 Public Primary Certification Authority - G5	| https://twitter.com/		|
| [thawte Primary Root CA][7]					|				|
| [thawte Primary Root CA - G3][7]				|				|
| SecureTrust CA						|				|
| QuoVadis Root CA 2						| https://supportforums.cisco.com/ |
| DST Root CA X3						| [Let's Encrypt](https://letsencrypt.org/) |

#### How to use the default list

Import the default CA list with:

````
cas.sh -C -P ~/.mozilla/firefox/XXXXXXXX.new_profile -a
````

## FAQ

**Why are obsolete/deprecated entries included in the user.js file?**

In case you want to use an older Firefox version (e.g. for test reasons) and normally it 
doesn't hurt your browser if there are old about:config preferences present.

**Installing the user.js file breaks xyz plugin/addon/extension, how can I fix it?**

See https://github.com/pyllyukko/user.js/issues/100

**Does this user.js file fix all security problems?**

No. Please report problems on the project's
[issue](https://github.com/pyllyukko/user.js/issues?q=is%3Aissue) tracker.

**Will there be an official addon/an android version/feature xyz?**

Search the project [issues](https://github.com/pyllyukko/user.js/issues?q=is%3Aissue).

**How can I lock my preferences to prevent Firefox overwriting them?**

See `lockPref` in [System-wide installation](#system-wide-installation).

## Contributing

Yes please! All issues and pull requests are more than welcome. Please try 
to break down your pull requests or commits into small / manageable entities,
so they are easier to process. All the settings in the ```user.js``` file
should have some official references to them, so the effect of those settings
can be easily verified from Mozilla's documentation.

Feel free to follow the latests commits [RSS feed](https://github.com/pyllyukko/user.js/commits/master.atom)
and other interesting feeds from the [References](#references) section.

For more information, see [CONTRIBUTING](https://github.com/pyllyukko/user.js/blob/master/CONTRIBUTING.md)

## References

#### Mozilla

* **[Security Advisories for Firefox](https://www.mozilla.org/security/known-vulnerabilities/firefox.html)**
* **[Known Vulnerabilities for Firefox](https://www.mozilla.org/en-US/security/known-vulnerabilities/firefox/)**
* **[DXR - All Firefox preferences](https://dxr.mozilla.org/mozilla-central/source/modules/libpref/init/all.js) ([RSS](https://dxr.mozilla.org/mozilla-central/source/modules/libpref/init/all.js))**
* **[Mozilla Security Blog](https://blog.mozilla.org/security/category/security/) ([RSS](https://blog.mozilla.org/security/feed/))**
* [Mozilla Firefox Release Plan](https://wiki.mozilla.org/RapidRelease/Calendar)
* [Mozilla Firefox developer release notes](https://developer.mozilla.org/en-US/Firefox/Releases)
* [Advices from Mozilla Firefox on privacy and government surveillance](https://www.mozilla.org/en-US/teach/smarton/surveillance/)
* [Polaris - advance privacy technnology for the web](https://wiki.mozilla.org/Polaris)
* [Mozilla Privacy Principles](https://wiki.mozilla.org/Privacy/Principles)
* [Mozilla preferences for uber-geeks](https://developer.mozilla.org/en-US/docs/Mozilla/Preferences/Mozilla_preferences_for_uber-geeks)
* [Privacy & Security related add-ons](https://addons.mozilla.org/firefox/extensions/privacy-security/) ([RSS](https://addons.mozilla.org/en-US/firefox/extensions/privacy-security/format:rss?sort=featured))

#### Other

* **[CVEs for Firefox - mitre.org](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=firefox)**
* [CVEs for Firefox - cvedetails.com](https://www.cvedetails.com/vulnerability-list/vendor_id-452/product_id-3264/Mozilla-Firefox.html) 
* [About:config entries - MozillaZine](http://kb.mozillazine.org/About:config_entries)
* [Security and privacy-related preferences - MozillaZine](http://kb.mozillazine.org/Category:Security_and_privacy-related_preferences)
* [Diff between various Firefox .js configurations in upcoming releases](https://cat-in-136.github.io/) **([RSS](https://cat-in-136.github.io/feed.xml))**
* [Center for Internet Security - Mozilla Firefox benchmarks](https://benchmarks.cisecurity.org/downloads/browse/index.cfm?category=benchmarks.desktop.browsers.firefox) ([RSS](https://benchmarks.cisecurity.org/downloads/rss/))
* [iSEC Tor Browser evaluation](https://github.com/iSECPartners/publications/tree/master/reports/Tor%20Browser%20Bundle)
* [The Design and Implementation of the Tor Browser](https://www.torproject.org/projects/torbrowser/design/)
* [Browser Exploitation Framework](https://beefproject.com/) [[1](http://blog.beefproject.com/) [2](https://github.com/beefproject/beef/wiki) [3](https://github.com/beefproject/beef)]
* [shadow - Firefox jemalloc heap exploitation framework](https://github.com/CENSUS/shadow)

#### TLS/SSL

* [Mozilla Included CA Certificate List](https://wiki.mozilla.org/CA:IncludedCAs)
* [Potentially problematic CA practices](https://wiki.mozilla.org/CA:Problematic_Practices)
* [Bulletproof SSL and TLS](https://www.feistyduck.com/books/bulletproof-ssl-and-tls/)
* [TLS Cipher Suite Discovery](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/TLS_Cipher_Suite_Discovery)
* [Server-side TLS configuration](https://wiki.mozilla.org/Security/Server_Side_TLS)

--------------------------------------------------------------------------

[1]: http://kb.mozillazine.org/User.js_file
[2]: https://wiki.mozilla.org/Security:Renegotiation#security.ssl.require_safe_negotiation
[3]: http://kb.mozillazine.org/Dom.storage.enabled
[4]: http://patrol.psyced.org/
[5]: https://blog.torproject.org/blog/life-without-ca
[6]: http://kb.mozillazine.org/About:config
[7]: https://www.thawte.com/roots/
[8]: https://support.mozilla.org/en-US/kb/Private%20Browsing
[9]: https://bugzilla.mozilla.org/show_bug.cgi?id=822869
[11]: https://www.entrust.com/products/developer-api-standards/
[12]: https://support.mozilla.org/en-US/kb/tracking-protection-firefox
[13]: https://www.mozilla.org/en-US/lightbeam/
[15]: https://mzl.la/NYhKHH
