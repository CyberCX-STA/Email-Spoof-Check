# Email Spoof Check

Audit your domain's SPF and DMARC configuration, particularly for overtake and impersonation (spoof) conditions.

### Dependencies

* Python 3

### Install

`pip3 install -r requirements.txt`

### Usage

Run `python3 email_spoof_check.py example.com` to audit an SPF and DMARC policy.

### Checks

* Whether an SPF record exists (or no-send record exists)
  * Whether the number of permitted senders is sane
  * Whether the number of DNS lookups is within 10 (RFC requirement)
  * Whether all hostnames are resolvable (RFC requirement)
  * Whether fradulant mail is hard-failed (`-all`)
  * Whether IPs overlap with cloud IPs members of the public can register (e.g EC2 IPs)
* Whether a DMARC policy exists
  * Whether 100% of emails are checked for compliance
  * Whether the policy is configured to reject fraudulent mail
  * Whether the policy is configured to reject fraudulent mail (subdomains)

### Example (fictional)

```
$ python3 email_spoof_check.py example.com

 _______ 
|==   []|  Email Spoof Check - Copyright CyberCX 2022
|  ==== |  Check a domain's SPF and DMARC records for spoofing conditions
'-------'

example.com's SPF record is:                                           

  v=spf1 include:spf.example.com include:example.mailprovider.com +mx ~all

    spf.example.com's SPF record is:

      v=spf1 ip4:192.168.0.100 include:spf2.example.org ~all

        spf2.example.com's SPF record is:

          v=spf1 ip6:DEAD:BEEF::/64 -all

    example.mailprovider.com's SPF record is:

      v=spf1 ip4:129.152.0.0/17 ~all

example.com's DMARC record is:

    v=DMARC1; p=none; pct=10; rua=mailto:indy@ag.dmarcian-ap.com

SPF record is defined - Spoofed mail is somewhat prevented
605706 IPs are permitted senders - Regularly review your SPF record to ensure the record is as least-permissive as possible
4 DNS lookup(s) were made - More than 10, and the record would be invalid
All hostnames were resolved - An irresolvable hostname may invalidate the entire record
~all directive leaves action ambiguous - Without a hard fail '-all' directive, mail clients will not take firm actions against spoofed mail
Permitted ranges are public-obtainable - This record contains CIDR ranges for IPs adversaries can obtain, allowing them to bypass SPF and spoof email for your domain
    129.152.0.0/17 overlaps 129.152.0.0/19 (OracleCloud) https://docs.oracle.com/en-us/iaas/Content/General/Concepts/addressranges.htm

DMARC record is defined - SPF policy is less ambiguous
Only 10% of email is covered by DMARC - Email can be spoofed 90% of the time
DMARC policy is not active - `p=none` is the equivalent of having no DMARC record, allowing spoofed mail
DMARC policy is active for subdomains - A rejection criteria is in use or implied
```
