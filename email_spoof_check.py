import ipaddr
import argparse
from sys import argv
from requests import get
from os.path import isfile
from dns.resolver import resolve, NXDOMAIN

# Setup globals
recurStr = []     # Array of records as they're found
totalIPs = 0      # Running total of recursive permitted IPs
lookups = 1       # Number of recursive DNS resolutions
CIDRs = []        # Array filled with public-obtainable CIDR ranges + custom
badCIDRs = []     # Overlapping IPs found in the recursive SPF record
CIDRmaps = {}     # Dict to attribute IP ranges to platforms
# False positive CIDR overlaps
FPcidrs = ["40.92.0.0/15", "52.100.0.0/14", "54.240.0.0/18"]
platformLinks = { # Links to CIDR sources
	"GCP": "https://cloud.google.com/compute/docs/faq#find_ip_range",
	"AWS": "https://docs.aws.amazon.com/general/latest/gr/aws-ip-ranges.html",
	"Azure": "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519",
	"DigitalOcean": "https://docs.digitalocean.com/products/platform/",
	"OracleCloud": "https://docs.oracle.com/en-us/iaas/Content/General/Concepts/addressranges.htm",
	"Custom": "Custom IP range"
}

# Catch arguments
parser = argparse.ArgumentParser(usage="Usage: python3 email_spoof_check.py -d example.com", add_help=True)
parser.add_argument("--domain", "-d", type=str, required=True, help="The domain to scan")
parser.add_argument("--refresh-ips", "-r", action='store_true', default=False, help="Pull fresh public-obtainable CIDR ranges")
parser.add_argument("--custom-ips", "-c", nargs="+", default=[], help="Custom IPs to flag as spoofable")
args = parser.parse_args()

# Banner
print(""" _______ 
|==   []|  Email Spoof Check - Copyright CyberCX 2022 - https://cybercx.com
|  ==== |  Check a domain's SPF and DMARC records for spoofing conditions
'-------'\n""")

# Grab fresh registrable public CIDRs if need be
if not isfile("IPs.txt") or args.refresh_ips:
	IPs = []
	print("Getting fresh CIDR ranges...")

	print("Pulling user-registrable GCP CIDRs...")
	json = get("https://www.gstatic.com/ipranges/cloud.json").json()
	for IPrange in json["prefixes"]:
		if "ipv4Prefix" in IPrange:
			IPs.append(f'{IPrange["ipv4Prefix"]}|GCP')

	print("Pulling user-registrable AWS CIDRs...")
	json = get("https://ip-ranges.amazonaws.com/ip-ranges.json").json()
	for IPrange in json["prefixes"]:
		if "ip_prefix" in IPrange and IPrange["service"] == "EC2":
			IPs.append(f'{IPrange["ip_prefix"]}|AWS')

	print("Pulling user-registrable Oracle Cloud CIDRs...")
	json = get("https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json").json()
	for region in json["regions"]:
		for cidr in region["cidrs"]:
			IPs.append(f'{cidr["cidr"]}|OracleCloud')

	print("Pulling user-registrable Digital Ocean CIDRs...")
	csv = get("https://www.digitalocean.com/geo/google.csv").text
	for line in csv.split("\n"):
		if "::" not in line and "/" in line:
			IPs.append(f'{line.split(",")[0]}|DigitalOcean')

	print("Pulling user-registrable Azure CIDRs...")
	azureIndirect = get("https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519", headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0"}).text.split("\n")
	for i, line in enumerate(azureIndirect):
		if "30 seconds" in line:
			azureDirect = azureIndirect[i+1].split(".json\"")[0].split('"')[-1] + ".json"
	json = get(azureDirect).json()
	for value in json["values"]:
		if "AzureCloud" in value["name"]:
			for cidr in value["properties"]["addressPrefixes"]:
				if "::" not in cidr:
					IPs.append(f'{cidr}|Azure')

	with open("IPs.txt", "w") as IPfile:
		IPfile.write("\n".join(IPs))

	print(f"Pulled {len(IPs)} CIDRs\n")

# The IP file is | delimited, so split and load into a python array / dict
with open("IPs.txt", "r") as rawCIDRs:
	lines = rawCIDRs.read().split("\n")
	for line in lines[:-1]:
		cidr, platform = line.split("|")
		CIDRs.append(ipaddr.IPNetwork(cidr))
		CIDRmaps[cidr] = platform

# Add any custom bad-CIDRs
for customCIDR in args.custom_ips:
	CIDRs.append(ipaddr.IPNetwork(customCIDR))
	CIDRmaps[customCIDR] = "Custom"

# Grab just the hostname in case a URL is supplied
domain = args.domain.strip("/").replace("http://", "").replace("https://", "").replace("www.", "")

# Helper decorator functions
def PaintY(s): return f"\033[93m{s}\033[00m"
def PaintB(s): return f"\033[44m{s}\033[00m"
def PaintR(s): return f"\033[41m{s}\033[00m\033[93m"
def Info(title, desc): print(f"\033[44m{title}\033[00m - {desc}")
def Warn(title, desc): print(f"\033[43m{title}\033[00m - {desc}")
def Crit(title, desc): print(f"\033[41m{title}\033[00m - {desc}")

# DNS resolves TXT record, filters and cleans them up
def PullRecs(host, match):
	try:
		rawRecs = resolve(host, "TXT", raise_on_no_answer=False)
	except NXDOMAIN:
		if "_" not in host:
			return "HOSTNAME_COULD_NOT_BE_RESOLVED"
		return ""
	recs = [str(r) for r in rawRecs if match in str(r).lower()]
	return recs[0].replace('" "',"").replace('"', "").strip() if recs else ""

# Recursive function to pull SPF records and collect stats
def RecurseSPF(host, depth=0):
	# Globals because otherwise you have to messily pass it with the recursion
	global recurStr, totalIPs, lookups
	spf = PullRecs(host, "v=spf1")
	print(f"Resolving {host}..." + " " * 20, end="\r")

	# Structure pretty print
	recurStr.append("    " * (depth * 1) + f"{PaintB(host)}'s SPF record is:\n")
	recurStr.append(PaintY("    " * (depth * 1) + "  " + spf.replace("HOSTNAME_COULD_NOT_BE_RESOLVED", PaintR("HOSTNAME_COULD_NOT_BE_RESOLVED")) + "\n"))

	# For each piece in the resolved record
	for part in spf.split(" "):
		part = part.strip("+")
		if part.startswith("ip4"):
			# Normalise = / : notation
			cidr = part.replace("=", ":").split(":")[1]
			# If it's a single IP then there's no overtake harm
			# (unless IP lease has lapsed)
			if "/" not in part or "/32" in part:
				totalIPs += 1
			else:
				partCIDR = ipaddr.IPNetwork(cidr)
				totalIPs += partCIDR.numhosts
				# For every SPF CIDR, check if it overlaps public IP CIDRs
				# ignoring false positives
				for CIDR in CIDRs:
					if partCIDR.overlaps(CIDR) and cidr not in FPcidrs:
						# Paint it red and mark it as bad
						recurStr[-1] = recurStr[-1].replace(cidr, PaintR(cidr))
						badCIDRs.append([cidr, str(CIDR)])
						break

		# Continue recursing the SPF record
		if part.startswith("include") or part.startswith("redirect"):
			lookups += 1
			host = part.replace("=", ":").split(":")[1]
			# Don't follow SPF macros
			if '{' not in host:
				RecurseSPF(host, depth + 1)

# Follow the SPF record tree and print progress as you go
RecurseSPF(domain)
print(" " * 70 + "\r" + "\n".join(recurStr))

# Pull and store the DMARC record (if persent)
dmarc = PullRecs("_dmarc." + domain, "v=dmarc1")
dmarcColoured = dmarc.replace("sp=none", PaintR("sp=none")).replace("p=none", PaintR("p=none"))
if "pct=" in dmarc and "pct=100" not in dmarc:
	dmarcPct = "pct=" + dmarc.replace(";", " ").split("pct=")[1].split(" ")[0]
	dmarcColoured = dmarcColoured.replace(dmarcPct, PaintR(dmarcPct))
print(f"{PaintB(domain)}'s DMARC record is:\n")
print(PaintY("    " + dmarcColoured + "\n"))

# =========================== Reporting ===========================

# No SPF record
if (totalIPs == 0) and ("v=spf1" not in "".join(recurStr)):
	Crit("No SPF record is defined", "Mail can be easily spoofed for this domain. Either implement a record, or explicitly set a no-send record for domains not designed to send mail: 'v=spf1 -all'")
else:
	Info("SPF record is defined", "Spoofed mail is somewhat prevented")

	# Too many permitted senders
	if totalIPs > 1000000:
		Crit(f"{totalIPs} IPs are permitted senders", "Regularly review your SPF record to ensure the record is as least-permissive as possible")
	elif totalIPs > 10000:
		Warn(f"{totalIPs} IPs are permitted senders", "Regularly review your SPF record to ensure the record is as least-permissive as possible")
	elif totalIPs > 0:
		Info(f"{totalIPs} IPs are permitted senders", "Regularly review your SPF record to ensure the record is as least-permissive as possible")

	# Too many DNS lookups - invalid
	if lookups > 10:
		Crit(f"{lookups} DNS lookups were made", "Most clients refuse and ignore SPF records that result in more than 10 DNS lookups")
	else:
		Info(f"{lookups} DNS lookup(s) were made", "More than 10, and the record would be invalid")

	# Non resolvable hostname
	if "HOSTNAME_COULD_NOT_BE_RESOLVED" in "".join(recurStr):
		Crit("A hostname could not be resolved", "The entire SPF record may be ignored by clients")
	else:
		Info("All hostnames were resolved", "An irresolvable hostname may invalidate the entire record")

	# No hard fail
	if "all" in recurStr[1] and not "-all" in recurStr[1]:
		Warn(f"{recurStr[1][-10:-6]} directive leaves action ambiguous", "Without a hard fail '-all' directive, mail clients will not take firm actions against spoofed mail")
	elif "-all" in recurStr[1]:
		Info("'-all' directive is in use", "Mail clients know to hard fail spoofed mail")

	# Public-obtainable CIDRs overlap
	if badCIDRs:
		Crit("Permitted ranges are public-obtainable", "This record contains CIDR ranges for IPs adversaries can obtain, allowing them to bypass SPF and spoof email for your domain")
		for CIDR in badCIDRs:
			print(f"    {CIDR[0]} overlaps {CIDR[1]} ({CIDRmaps[CIDR[1]]}) {platformLinks[CIDRmaps[CIDR[1]]]}")
	else:
		Info("No common public-obtainable IP ranges exist", "E.g no EC2, Digital Ocean etc. IP ranges are present in the record that would allow adversaries to bypass SPF")

print()
# No DMARC policy exists
if not dmarc:
	Crit("No DMARC record is defined", "This can leave the SPF policy ambiguous")
else:
	Info("DMARC record is defined", "SPF policy is less ambiguous")

	# 100% of mail is not covered
	if "pct=" in dmarc and "pct=100" not in dmarc:
		pct = int(dmarc.replace(";", " ").split("pct=")[1].split(" ")[0])
		Crit(f"Only {pct}% of email is covered by DMARC", f"Email can be spoofed {100-pct}% of the time")
	else:
		Info("100% of email is covered", "The policy is not in a phased rollout")

	# Policy is set to none
	if " p=none" in dmarc.replace(";", " "):
		Crit("DMARC policy is not active", "`p=none` is the equivalent of having no DMARC record, allowing spoofed mail")
	else:
		Info("DMARC policy is active", "A rejection criteria is in use or implied")

	# Subdomain policy is set to none
	if " sp=none" in dmarc.replace(";", " "):
		Crit("DMARC policy is not active for subdomains", "`sp=none` is the equivalent of having no DMARC record for subdomains, allowing spoofed mail")
	else:
		Info("DMARC policy is active for subdomains", "A rejection criteria is in use or implied")
