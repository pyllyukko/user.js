# Limiting trust in Certificate Authorities


It all started when I read [this blog post][5]...

So another part of my browser hardening was to somehow reduce the number of CAs trusted by my browser. First I thought I would sniff all the HTTPS connections and extract the certificates from there, to get the list of CAs I **really** need.

Then I came up with an better idea. I'd use [certpatrol](http://patrol.psyced.org/) to record the certs from the HTTPS sites I visit. There was just one problem, certpatrol only stores the fingerprint of the issuer cert, which is usually a [intermediate CA](https://en.wikipedia.org/wiki/Intermediate_certificate_authorities). So I needed to get the root CA of the intermediate CA. The solution for this to use Firefox's *cert8.db* to extract the intermediate CAs and get the issuer (root CA) from there.

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


--------------------------------------------------------------------------------

[5]: https://blog.torproject.org/blog/life-without-ca
[7]: https://www.thawte.com/roots/
[11]: https://www.entrust.com/products/developer-api-standards/
