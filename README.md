Firefox hardening
=================

What's all this then?
---------------------

This is a [user.js][1] configuration file for Mozilla Firefox that's supposed to harden Firefox's settings and make it more secure.

### Main goals

* Limit the possibilities to track the user through [web analytics](https://en.wikipedia.org/wiki/Web_analytics)
* Harden the browser, so it doesn't spill it's guts when asked (have you seen what [BeEF](http://beefproject.com/) can do?)
* Limit the browser from storing anything even remotely sensitive persistently (mostly just making sure private browsing is always on)
* Make sure the browser doesn't reveal too much information to [shoulder surfers](https://en.wikipedia.org/wiki/Shoulder_surfing_%28computer_security%29)
* Harden the browser's encryption (cipher suites, protocols, trusted CAs)
* Still be at least somewhat usable in daily use

### How to achieve this?

There are several parts to all this and they are:

* Running a selected list of browser extensions
* Using the user.js settings file itself
* Using the **cas.sh** script to limit the CAs

#### How to use the user.js file

Just drop the [user.js][1] file to your Firefox profile directory at ````~/.mozilla/firefox/XXXXXXXX.your_profile_name```` and verify that the settings are effective from [about:config][6].

What does it do?
----------------

**DISCLAIMER**: This is not a complete list. Read the js file for more details :)

There's a whole lot of settings that this modifies and here are the main parts:

* Permanently enables [private browsing mode](https://support.mozilla.org/en-US/kb/Private%20Browsing)
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

Some of the settings in this [user.js][1] file might seem redundant, as some of them are already set to the same values by default. However, the [user.js][1] file has this nice property, that even if you go change any of these settings through [about:config](http://kb.mozillazine.org/About:config), they're reset to the [user.js][1] defined values after you restart Firefox. So [user.js][1] makes sure they're back at the secure default values always when you start your browser. That way, it also makes experimenting with different settings easier.

### HTTP headers

* Enables [DNT](https://en.wikipedia.org/wiki/Do_Not_Track) (like it matters)
* Disables referer headers:
  * [Network.http.sendRefererHeader](http://kb.mozillazine.org/Network.http.sendRefererHeader#0)
  * [Network.http.sendSecureXSiteReferrer](http://kb.mozillazine.org/Network.http.sendSecureXSiteReferrer)

### HTML5 related

* Don't reveal internal [IP addresses](http://net.ipcalf.com/) ([media.peerconnection.enabled](https://blog.mozilla.org/futurereleases/2013/01/12/capture-local-camera-and-microphone-streams-with-getusermedia-now-enabled-in-firefox/))
* [browser.send_pings](http://kb.mozillazine.org/Browser.send_pings)

### Ciphers

Hardens the used cipher suites and protocols.

* TLS v1.[012] only
* Require [OCSP](https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol)
  * Notice that this setting has some privacy implications
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
  * I recommend setting the 'Store certificates even when in Private Browsing Mode' to get full benefit out of certpatrol, even though it stores information about the sites you visit
* [HTTPS Everywhere](https://www.eff.org/https-everywhere)
* [NoScript](http://noscript.net/)
* [Ghostery](https://www.ghostery.com/)
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
* If you get "ssl\_error\_unsafe\_negotiation", it means the server is vulnerable to [CVE-2009-3555](http://www.cvedetails.com/cve/CVE-2009-3555) and you need to disable [security.ssl.require\_safe\_negotiation][2]
* If you set browser.frames.enabled to false, probably a whole bunch of websites will break
* Some sites require the [referer](https://en.wikipedia.org/wiki/HTTP_referer) header

The [web console](https://developer.mozilla.org/en-US/docs/Tools/Web_Console) is your friend, **when** websites start to break.

CAs
---

It all started when I read [this blog post][5]...

So another part of my browser hardening was to somehow reduce the number of CAs trusted by my browser. First I thought I would sniff all the HTTPS connections and extract the certificates from there, to get the list of CAs I **really** need.

Then I came up with an better idea. I'd use [certpatrol][4] to record the certs from the HTTPS sites I visit. There was just one problem, certpatrol only stores the fingerprint of the issuer cert, which is usually a [intermediate CA](https://en.wikipedia.org/wiki/Intermediate_certificate_authorities). So I needed to get the root CA of the intermediate CA. The solution for this to use Firefox's *cert8.db* to extract the intermediate CAs and get the issuer (root CA) from there.

So I wrapped up a script that uses the certpatrol's SQLite DB and Mozilla's [certutil](https://developer.mozilla.org/en-US/docs/NSS_security_tools/certutil) to establish a list of required root CAs from the HTTPS sites that you have visited.

There's also a ready made list built in into the script, that has 21 root CAs in it. With this list of CAs you should already be able to browse the web quite freely. Of course there might also be some geographical variations as to what CAs "are required" for normal use.

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

### The default list

<table>
  <tr>
    <th>Root CA</th><th>Used by</th>

  </tr>
<tr><td>AddTrust External CA Root</td>				<td>https://www.debian.org/</td></tr>
<tr><td>Baltimore CyberTrust Root</td>				<td></td></tr>
<tr><td>COMODO Certification Authority</td>			<td></td></tr>
<tr><td>Deutsche Telekom Root CA 2</td>				<td></td></tr>
<tr><td>DigiCert High Assurance EV Root CA</td>			<td>https://www.facebook.com/</td></tr>
<tr><td>DigiCert Global Root CA</td>				<td>https://duckduckgo.com/</td></tr>
<tr><td>Entrust.net Secure Server Certification Authority</td>	<td></td></tr>
<tr><td>Entrust.net Certification Authority (2048)</td>		<td></td></tr>
<tr><td>Equifax Secure Certificate Authority</td>		<td></td></tr>
<tr><td>GTE CyberTrust Global Root</td>				<td></td></tr>
<tr><td>GeoTrust Global CA</td>					<td>https://www.google.com/</td></tr>
<tr><td>GlobalSign Root CA</td>					<td>https://www.wikipedia.org/</td></tr>
<tr><td>Go Daddy Class 2 Certification Authority</td>		<td></td></tr>
<tr><td>Go Daddy Root Certificate Authority - G2</td>		<td></td></tr>
<tr><td>Starfield Class 2 Certification Authority</td>		<td>https://tools.ietf.org/</td></tr>
<tr><td>StartCom Certification Authority</td>			<td></td></tr>
<tr><td>UTN-USERFirst-Hardware</td>				<td></td></tr>
<tr><td>ValiCert Class 2 Policy Validation Authority</td>	<td></td></tr>
<tr><td>VeriSign Class 3 Public Primary Certification Authority - G5</td><td>https://twitter.com/</td></tr>
<tr><td>thawte Primary Root CA</td>				<td></td></tr>
<tr><td>SecureTrust CA</td>					<td></td></tr>
</table>


TODO
----

* [HTML5 canvas](https://en.wikipedia.org/wiki/Canvas_element)
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
