Firefox hardening
=================

What's all this then?
---------------------

This is a [user.js][1] configuration file for Mozilla Firefox that's supposed to harden Firefox's settings and make it more secure.

### Main goals

* Limit the possibilities to track the user through [web analytics](https://en.wikipedia.org/wiki/Web_analytics)
* Harden the browser, so it doesn't spill it's guts when asked (have you seen what [BeEF](http://beefproject.com/) can do?)
* Limit the browser from storing anything even remotely sensitive persistently (mostly just making sure [private browsing][8] is always on)
* Make sure the browser doesn't reveal too much information to [shoulder surfers](https://en.wikipedia.org/wiki/Shoulder_surfing_%28computer_security%29)
* Harden the browser's encryption (cipher suites, protocols, trusted CAs)
* Still be at least somewhat usable in daily use

### How to achieve this?

There are several parts to all this and they are:

* Running a selected list of browser extensions
* Using the user.js settings file itself
* Using the **cas.sh** script to limit the CAs

#### How to use the user.js file

Just drop the [user.js][1] file to your Firefox profile directory at ````~/.mozilla/firefox/XXXXXXXX.your_profile_name```` and verify that the settings are effective from [about:support](http://kb.mozillazine.org/Troubleshooting_Information_report#Modified_Preferences) (check the "Important Modified Preferences" and "user.js Preferences" sections).

If you want to be able to keep your [user.js][1] up-to-date with this repository, you can clone the latter in the main mozilla directory and create a link to the [user.js][1] file from your profile:
````
cd ~/.mozilla/firefox
git clone 'https://github.com/pyllyukko/user.js.git'
cd XXXXXXXX.your_profile_name
ln -s ../user.js/user.js user.js
````

Whenever you want to update your local copy of the repository, just use ````git pull```` and restart firefox.

What does it do?
----------------

**DISCLAIMER**: This is not a complete list. Read the js file for more details :)

There's a whole lot of settings that this modifies and here are the main parts:

* Permanently enables [private browsing][8] mode
* Enables Firefox's [mixed content blocking](https://blog.mozilla.org/tanvi/2013/04/10/mixed-content-blocking-enabled-in-firefox-23/) (also for "display" content)
* Disables various your-browser-knows-better-let-me-guess-what-you-were-trying features
  * Disable this [keyword thingie](http://kb.mozillazine.org/Keyword.enabled)
  * Disable [Domain Guessing](http://www-archive.mozilla.org/docs/end-user/domain-guessing.html)
  * Disable [search suggestions](http://kb.mozillazine.org/Browser.search.suggest.enabled)
* Disables [telemetry](https://wiki.mozilla.org/Telemetry), [geolocation](https://www.mozilla.org/en-US/firefox/geolocation/), [Crash Reporter](https://support.mozilla.org/en-US/kb/Mozilla%20Crash%20Reporter) and other such privacy invading nonsense
* Don't [suggest any URLs](http://kb.mozillazine.org/Browser.urlbar.maxRichResults) while typing at the address bar
* Disables prefetching
  * [network.prefetch-next](http://kb.mozillazine.org/Network.prefetch-next)
  * [network.dns.disablePrefetch](http://kb.mozillazine.org/Network.dns.disablePrefetch)
* Prevents Firefox from storing data filled in web page forms

Some of the settings in this [user.js][1] file might seem redundant, as some of them are already set to the same values by default. However, the [user.js][1] file has this nice property, that even if you go change any of these settings through [about:config][6], they're reset to the [user.js][1] defined values after you restart Firefox. So [user.js][1] makes sure they're back at the secure default values always when you start your browser. That way, it also makes experimenting with different settings easier.

### HTTP headers

* Enables [DNT](https://en.wikipedia.org/wiki/Do_Not_Track) (like it matters)
* Referer header:
  * Spoofs the referer header with [network.http.referer.spoofSource](https://bugzilla.mozilla.org/show_bug.cgi?id=822869) &  [Network.http.sendRefererHeader](http://kb.mozillazine.org/Network.http.sendRefererHeader#1)
  * "[Don't send the Referer header when navigating from a https site to another https site.](http://kb.mozillazine.org/Network.http.sendSecureXSiteReferrer#false)"

### HTML5 related

* Don't reveal internal [IP addresses](http://net.ipcalf.com/) ([media.peerconnection.enabled](https://blog.mozilla.org/futurereleases/2013/01/12/capture-local-camera-and-microphone-streams-with-getusermedia-now-enabled-in-firefox/))
* [browser.send_pings](http://kb.mozillazine.org/Browser.send_pings)

### Ciphers

Hardens the used cipher suites and protocols.

* TLS v1.[012] only
* Require [OCSP](https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol)
  * Notice that this setting has some [privacy implications](https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol#Privacy_concerns)
* [OCSP stapling](https://blog.mozilla.org/security/2013/07/29/ocsp-stapling-in-firefox/) (enabled by default anyway)
* Disable [TLS session tickets](https://www.blackhat.com/us-13/archives.html#NextGen)
* Enforces [pinning](https://wiki.mozilla.org/SecurityEngineering/Public_Key_Pinning)

Here's a list of the ciphers with default config and Firefox 27.0.1:

	Cipher Suites (23 suites)
	    Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)
	    Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)
	    Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a)
	    Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009)
	    Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)
	    Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)
	    Cipher Suite: TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA (0xc012)
	    Cipher Suite: TLS_ECDHE_ECDSA_WITH_RC4_128_SHA (0xc007)
	    Cipher Suite: TLS_ECDHE_RSA_WITH_RC4_128_SHA (0xc011)
	    Cipher Suite: TLS_DHE_RSA_WITH_AES_128_CBC_SHA (0x0033)
	    Cipher Suite: TLS_DHE_DSS_WITH_AES_128_CBC_SHA (0x0032)
	    Cipher Suite: TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA (0x0045)
	    Cipher Suite: TLS_DHE_RSA_WITH_AES_256_CBC_SHA (0x0039)
	    Cipher Suite: TLS_DHE_DSS_WITH_AES_256_CBC_SHA (0x0038)
	    Cipher Suite: TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA (0x0088)
	    Cipher Suite: TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA (0x0016)
	    Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
	    Cipher Suite: TLS_RSA_WITH_CAMELLIA_128_CBC_SHA (0x0041)
	    Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)
	    Cipher Suite: TLS_RSA_WITH_CAMELLIA_256_CBC_SHA (0x0084)
	    Cipher Suite: TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000a)
	    Cipher Suite: TLS_RSA_WITH_RC4_128_SHA (0x0005)
	    Cipher Suite: TLS_RSA_WITH_RC4_128_MD5 (0x0004)

Here's the list with this config:

	Cipher Suites (9 suites)
	    Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)
	    Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)
	    Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a)
	    Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)
	    Cipher Suite: TLS_DHE_RSA_WITH_AES_256_CBC_SHA (0x0039)
	    Cipher Suite: TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA (0x0088)
	    Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
	    Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)
	    Cipher Suite: TLS_RSA_WITH_RC4_128_SHA (0x0005)

This is not enough!
-------------------

Here's some other tips how you can further harden Firefox:

* Disable all unnecessary extensions and plugins!
* [Certificate Patrol][4]
  * I recommend setting the 'Store certificates even when in [Private Browsing][8] Mode' to get full benefit out of certpatrol, even though it stores information about the sites you visit
* [HTTPS Everywhere](https://www.eff.org/https-everywhere)
* [NoScript](http://noscript.net/)
* [Ghostery](https://www.ghostery.com/)
* [Privacy Badger](https://www.eff.org/privacybadger)
* [DuckDuckGo Plus](https://addons.mozilla.org/en-US/firefox/addon/duckduckgo-for-firefox/) (instead of Google)
* [Mozilla Lightbeam](https://www.mozilla.org/en-US/lightbeam/)
* Create different [profiles](http://mzl.la/NYhKHH) for different purposes

Online tests
------------

* [Panopticlick](https://panopticlick.eff.org/)
* [www.filldisk.com](http://www.filldisk.com/)
* [HTML5test](http://html5test.com/)
* [SSL Client Test](https://www.ssllabs.com/ssltest/viewMyClient.html)
* [evercookie](http://samy.pl/evercookie/)
* [Mozilla Plugin Check](https://www.mozilla.org/en-US/plugincheck/)
* [BrowserSpy.dk](http://browserspy.dk/)
* [Testing mixed content](https://people.mozilla.org/~tvyas/mixedcontent.html)
  * [Similar from Microsoft](https://ie.microsoft.com/testdrive/browser/mixedcontent/assets/woodgrove.htm)
* [WebRTC stuff](http://mozilla.github.io/webrtc-landing/)
* [Flash player version](https://www.adobe.com/software/flash/about/) from Adobe
* [Verify Java Version](https://www.java.com/en/download/installed.jsp)
  * Protip: Don't use Java!! But if you do, at least have it updated.
* [IP check](http://ip-check.info/?lang=en)
* http://cure53.de/leak/onion.php
* [Firefox Addon Detector](http://thehackerblog.com/addon_scanner/)
  * [Blog post](http://thehackerblog.com/dirty-browser-enumeration-tricks-using-chrome-and-about-to-detect-firefox-plugins/)
* [browserrecon](http://www.computec.ch/projekte/browserrecon/)??

Known problems
--------------

There are plenty! Hardening your browser will break your interwebs. Here's some examples:

* If you get "TypeError: localStorage is null", you probably need to enable [local storage][3]
* If you get "sec\_error\_ocsp\_invalid\_signing\_cert", it probably means that you don't have the required CA
* If you get "ssl\_error\_unsafe\_negotiation", it means the server is vulnerable to [CVE-2009-3555](http://www.cvedetails.com/cve/CVE-2009-3555) and you need to disable [security.ssl.require\_safe\_negotiation][2] (not enabled currently)
* If you set browser.frames.enabled to false, probably a whole bunch of websites will break
* Some sites require the [referer](https://en.wikipedia.org/wiki/HTTP_referer) header
* The [IndexedDB](https://en.wikipedia.org/wiki/Indexed_Database_API) is something that could potentially be used to track users, but it is also required by some browser add-ons in recent versions of Firefox. It would be best to disable this feature just to be on the safe side, but it is currently enabled, so that add-ons would work. See the following links for further info:
  * [Issue #8](https://github.com/pyllyukko/user.js/issues/8)
  * [IndexedDB Security Review](https://wiki.mozilla.org/Security/Reviews/Firefox4/IndexedDB_Security_Review) (this document also states that "IndexedDB is completely disabled in private browsing mode.", but this should still be verified)
  * [This discussion](http://forums.mozillazine.org/viewtopic.php?p=13842047&sid=041e5edcae225759b7cfffd43fc518d0#p13842047) on mozillaZine Forums
  * [IndexedDB page at MDN](https://developer.mozilla.org/en-US/docs/IndexedDB)
* It would be nice to get completely rid of [RC4](https://en.wikipedia.org/wiki/RC4#Security), but it doesn't seem quite possible currently
  * ([CVE-2013-2566](http://www.cvedetails.com/cve/CVE-2013-2566))

The [web console](https://developer.mozilla.org/en-US/docs/Tools/Web_Console) is your friend, **when** websites start to break.

CAs
---

It all started when I read [this blog post][5]...

So another part of my browser hardening was to somehow reduce the number of CAs trusted by my browser. First I thought I would sniff all the HTTPS connections and extract the certificates from there, to get the list of CAs I **really** need.

Then I came up with an better idea. I'd use [certpatrol][4] to record the certs from the HTTPS sites I visit. There was just one problem, certpatrol only stores the fingerprint of the issuer cert, which is usually a [intermediate CA](https://en.wikipedia.org/wiki/Intermediate_certificate_authorities). So I needed to get the root CA of the intermediate CA. The solution for this to use Firefox's *cert8.db* to extract the intermediate CAs and get the issuer (root CA) from there.

So I wrapped up a script that uses the certpatrol's SQLite DB and Mozilla's [certutil](https://developer.mozilla.org/en-US/docs/NSS_security_tools/certutil) to establish a list of required root CAs from the HTTPS sites that you have visited.

There's also a ready made list built in into the script, that has 22 root CAs in it. With this list of CAs you should already be able to browse the web quite freely. Of course there might also be some geographical variations as to what CAs "are required" for normal use.

### Examples

**Do note**, that in order for all this to work, you **MUST** remove or rename Firefox's default CA list that is stored inside *libnssckbi.so* as described [here][5].

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
| Equifax Secure Certificate Authority				|				|
| GTE CyberTrust Global Root					|				|
| GeoTrust Global CA						| https://www.google.com/	|
| GlobalSign Root CA						| https://www.wikipedia.org/	|
| Go Daddy Class 2 Certification Authority			|				|
| Go Daddy Root Certificate Authority - G2			|				|
| Starfield Class 2 Certification Authority			| https://tools.ietf.org/	|
| StartCom Certification Authority				|				|
| UTN-USERFirst-Hardware					|				|
| ValiCert Class 2 Policy Validation Authority			|				|
| VeriSign Class 3 Public Primary Certification Authority - G5	| https://twitter.com/		|
| [thawte Primary Root CA][7]					|				|
| [thawte Primary Root CA - G3][7]				|				|
| SecureTrust CA						|				|

#### How to use the default list

Import the default CA list with:

````
cas.sh -C -P ~/.mozilla/firefox/XXXXXXXX.new_profile -a
````


TODO
----

* [HTML5 canvas](https://en.wikipedia.org/wiki/Canvas_element)
  * [Canvas fingerprinting](https://en.wikipedia.org/wiki/Canvas_fingerprinting)
  * [BrowserLeaks.com](https://www.browserleaks.com/canvas)
  * https://developer.mozilla.org/en-US/docs/HTML/Canvas
  * https://www.torproject.org/projects/torbrowser/design/#fingerprinting-linkability
  * [Bug 967895](https://bugzilla.mozilla.org/show_bug.cgi?id=967895)
  * [Pixel Perfect: Fingerprinting Canvas in HTML5](http://www.w2spconf.com/2012/papers/w2sp12-final4.pdf)
* [Address Sanitizer](https://developer.mozilla.org/en-US/docs/Building_Firefox_with_Address_Sanitizer)

References
----------

* [CIS Mozilla Firefox Benchmark v1.2.0](http://benchmarks.cisecurity.org/downloads/show-single/?file=firefox.120)
* [Security Advisories for Firefox](https://www.mozilla.org/security/known-vulnerabilities/firefox.html)
* [The Design and Implementation of the Tor Browser](https://www.torproject.org/projects/torbrowser/design/)
* [Bulletproof SSL and TLS](https://www.feistyduck.com/books/bulletproof-ssl-and-tls/)
* [Polaris](https://wiki.mozilla.org/Polaris)
* [Mozilla Included CA Certificate List](http://www.mozilla.org/projects/security/certs/included)

[1]: http://kb.mozillazine.org/User.js_file
[2]: https://wiki.mozilla.org/Security:Renegotiation#security.ssl.require_safe_negotiation
[3]: http://kb.mozillazine.org/Dom.storage.enabled
[4]: http://patrol.psyced.org/
[5]: https://blog.torproject.org/blog/life-without-ca
[6]: http://kb.mozillazine.org/About:config
[7]: https://www.thawte.com/roots/
[8]: https://support.mozilla.org/en-US/kb/Private%20Browsing
