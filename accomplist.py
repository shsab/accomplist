#!/usr/bin/env python2
# -*- coding: utf-8 -*-
'''
=========================================================================================
 accomplist.py: v1.31-201801 Copyright (C) 2018 Chris Buijs <cbuijs@chrisbuijs.com>
=========================================================================================

Blocklist (Black/Whitelist) compiler/optimizer.

TODO:

- !!! Better Documentation / Remarks / Comments

=========================================================================================
'''

## Modules

# Make sure modules can be found
import sys
sys.path.append("/usr/local/lib/python2.7/dist-packages/")

# Standard/Included modules
import os, os.path, time, shelve
from copy import deepcopy

# Use requests module for downloading lists
import requests

# Use module regex instead of re, much faster less bugs
import regex

# Use module pytricia to find ip's in CIDR's dicts fast
import pytricia

# Use IPSet from IPy to aggregate
from IPy import IP, IPSet

# Use unicode-data to normalize inputs
import unicodedata

##########################################################################################

## Variables/Dictionaries/Etc ...

# Sources file to configure which lists to use
if len(sys.argv) > 2:
    sources = str(sys.argv[1])
    outputdir = str(sys.argv[2])
    workdir = outputdir + '/work'
else:
    sources = '/opt/accomplist/accomplist.sources'
    outputdir = '/opt/accomplist/default'
    workdir = '/opt/accomplist/default/work'

# IPASN
asnip = dict()
ipasnfile = '/opt/ipasn/ipasn-all.dat'
ipasnoutfile = '/opt/accomplist/ipasn-all-cidr-aggregated.dat'
ipasnfilecache = '/opt/accomplist/ipasn.cache'

# Lists
blacklist = dict() # Domains blacklist
whitelist = dict() # Domains whitelist
cblacklist4 = pytricia.PyTricia(32) # IPv4 blacklist
cwhitelist4 = pytricia.PyTricia(32) # IPv4 whitelist
cblacklist6 = pytricia.PyTricia(128) # IPv6 blacklist
cwhitelist6 = pytricia.PyTricia(128) # IPv6 whitelist
rblacklist = dict() # Regex blacklist (maybe replace with set()?)
rwhitelist = dict() # Regex whitelist (maybe replace with set()?)
excludelist = dict() # Domain excludelist
asnwhitelist = dict() # ASN Whitelist
asnblacklist = dict() # ASN Blacklist
safeblacklist = dict() # Safe blacklist anything is this list will not be touched
safewhitelist = dict() # Safe whitelist anything is this list will not be touched
safeunwhitelist = dict() # Keep unwhitelisted entries safe

# Save
blacksave = outputdir + '/black.list'
whitesave = outputdir + '/white.list'
genericblacksave = outputdir + '/black.generic.list'
genericwhitesave = outputdir + '/white.generic.list'

# regexlist
fileregex = dict()
fileregexlist = '/opt/accomplist/accomplist.listregexes'

# TLD file
tldlist = dict()
tldfile = workdir + '/iana-tlds.list'

# Unwhitelist domains, keep in mind this can remove whitelisted entries that are blocked by IP.
unwhitelist = False

# Allow RFC 2606 TLD's
rfc2606 = False

# Allow common intranet TLD's
intranet = False

# Allow block internet domains
notinternet = False

# Aggregate IP lists, can be slow on large list (more then 5000 entries)
aggregate = True # if false, only child subnets will be removed

# Creaete automatic white-safelist entries that are unwhitelisted
autowhitesafelist = True

# Default maximum age of downloaded lists, can be overruled in lists file
maxlistage = 7200 # In seconds

# Debug-level, the higher levels include the lower level informations
debug = 2

## Regexes

# Default file regex
defaultfregex = '^(?P<line>.*)$'

# Regex to match IPv4/IPv6 Addresses/Subnets (CIDR)
ip4regex = '((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}(/(3[0-2]|[12]?[0-9]))*)'
ip6regex = '(((:(:[0-9a-f]{1,4}){1,7}|::|[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,6}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,5}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,4}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,3}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,2}|::|:[0-9a-f]{1,4}(::[0-9a-f]{1,4}|::|:[0-9a-f]{1,4}(::|:[0-9a-f]{1,4}))))))))|(:(:[0-9a-f]{1,4}){0,5}|[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){0,4}|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){0,3}|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){0,2}|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4})?|:[0-9a-f]{1,4}(:|:[0-9a-f]{1,4})))))):(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})(/(12[0-8]|1[01][0-9]|[1-9]?[0-9]))*)'
ipregex = regex.compile('^(' + ip4regex + '|' + ip6regex +')$', regex.I)

# Regex to match regex-entries in lists
isregex = regex.compile('^/.*/$')

# Regex for AS(N) number
asnregex = regex.compile('^AS[0-9]+$')

# Regex to match domains/hosts in lists
isdomain = regex.compile('^[a-z0-9_\.\-]+$', regex.I) # According RFC plus underscore, works everywhere

# Regex for excluded entries to fix issues
defaultexclude = '^(127\.0\.0\.1(/32)*|::1(/128)*|local(host|net[s]*))$'
exclude = regex.compile(defaultexclude, regex.I)

# Regex for www entries
wwwregex = regex.compile('^(https*|ftps*|www*)[0-9]*\..*$', regex.I)

##########################################################################################

# Info messages
def log_info(msg):
    print(msg)
    return


# Error messages
def log_err(msg):
    print(msg)
    return


# Check against REGEX lists
def check_regex(name, bw):
    if (bw == 'black'):
        rlist = rblacklist
    else:
        rlist = rwhitelist

    for i in range(0,len(rlist)/3):
        checkregex = rlist[i,1]
        if (debug >= 3): log_info('Checking ' + name + ' against regex \"' + rlist[i,2] + '\"')
        if checkregex.search(name):
            return '\"' + rlist[i,2] + '\" (' + rlist[i,0] + ')'
        
    return False


# Add exclusions to lists
def add_exclusion(dlist, elist, slist, listname):
    before = len(dlist)

    for domain in dom_sort(elist.keys()):
        id = elist[domain]
        if (debug >= 2): log_info('Adding excluded entry \"' + domain + '\" to ' + listname + ' (from ' + id + ')')
        if domain in dlist:
            if dlist[domain].find(id) == -1:
                dlist[domain] = dlist[domain] + ', ' + id
        else:
            dlist[domain] = id

        slist[domain] = id

    after = len(dlist)
    count = after - before

    if (debug >= 2): log_info('Added ' + str(count) + ' new exclusion entries to \"' + listname + '\", went from ' + str(before) + ' to ' + str(after))

    return dlist


# Read file/list
def read_lists(id, name, regexlist, iplist4, iplist6, domainlist, asnlist, safelist, safewlist, force, bw):
    orgid = id

    addtolist = dict()

    if (len(name) > 0):
        try:
            with open(name, 'r') as f:
                log_info('Reading ' + bw + '-file/list \"' + name + '\" (' + id + ')')
         
                orgregexcount = (len(regexlist)/3-1)+1
                regexcount = orgregexcount
                ipcount = 0
                domaincount = 0
                asncount = 0
                skipped = 0
                total = 0

                for line in f:
                    entry = line.split('#')[0].strip().replace('\r', '')
                    if len(entry) > 0 and (not entry.startswith('#')):
                        id = orgid
                        elements = entry.split('\t')
                        if len(elements) > 1:
                            entry = elements[0]
                            if elements[1]:
                                id = elements[1]

                        safed = False
                        if (safelist != False) and entry.endswith('!'):
                            entry = entry[:-1]
                            safed = True

                        unwhite = False
                        if (not safed) and (unwhitelist != False) and entry.endswith('&'):
                            entry = entry[:-1]
                            unwhite = True

                        total += 1
                        if (isregex.match(entry)):
                            # It is an Regex
                            cleanregex = entry.strip('/')
                            try:
                                regexlist[regexcount,1] = regex.compile(cleanregex, regex.I)
                                regexlist[regexcount,0] = str(id)
                                regexlist[regexcount,2] = cleanregex
                                regexcount += 1
                            except:
                                log_err(name + ': Skipped invalid line/regex \"' + entry + '\"')
                                pass

                        elif (asnregex.match(entry.upper())):
                            entry = entry.upper()
                            if entry in asnlist:
                                if asnlist[entry].find(id) == -1:
                                    asnlist[entry] = asnlist[entry] + ', ' + id

                                skipped += 1
                            else:
                                asnlist[entry] = id
                                asncount += 1

                            if ipasnfile:
                                asn = entry[2:]
                                lst = asnip.get(asn, list())
                                for ip in lst:
                                    if (debug >= 3): log_info('Added ' + ip + ' from ASN ' + entry)
                                    if add_cidr(iplist4, iplist6, ip, id + '-' + entry):
                                        ipcount += 1
                                    else:
                                        skipped += 1

                        elif (ipregex.match(entry)):
                            # It is an IP
                            if add_cidr(iplist4, iplist6, entry, id):
                                ipcount += 1
                            else:
                                skipped += 1

                        elif (isdomain.match(entry)):
                                # It is a domain
                                domain = entry.strip('.').lower()

                                # Strip 'www." if appropiate
                                if wwwregex.match(domain) and domain.count('.') > 1:
                                    label = domain.split('.')[0]
                                    newdomain = '.'.join(domain.split('.')[1:])
                                    if (debug >= 3): log_info('Stripped \"' + label + '\" from \"' + domain + '\" (' + newdomain + ')')
                                    domain = newdomain

                                if domain:
                                    if tldlist and (not force) and (not safed):
                                        tld = domain.split('.')[-1:][0]
                                        if not tld in tldlist:
                                            if (debug >= 2): log_info('Skipped DOMAIN \"' + domain + '\", TLD (' + tld + ') does not exist')
                                            domain = False
                                            addtolist[tld] = 'Invalid-TLD-' + id
                                            skipped += 1

                                    if domain:
                                        if unwhite:
                                            if (debug >= 2): log_info('Added \"' + domain + '\" to ' + 'safe-unwhite-list')
                                            safewlist[domain] = id
                                            skipped += 1

                                        else:
                                            if safed:
                                                if (debug >= 2): log_info('Added \"' + domain + '\" to ' + bw + '-safelist')
                                                safelist[domain] = 'Safelist'

                                            if domain in domainlist:
                                                if domainlist[domain].find(id) == -1:
                                                    domainlist[domain] = domainlist[domain] + ', ' + id

                                                skipped += 1

                                            else:
                                                domainlist[domain] = id
                                                domaincount += 1

                        else:
                            log_err(name + ': Skipped invalid line \"' + entry + '\"')
                            skipped += 1

                if (debug >= 2): log_info('Processed ' + bw + 'list ' + str(total) + ' entries and skipped ' + str(skipped) + ' (existing/invalid) ones from \"' + orgid + '\"')
                if (debug >= 1): log_info('Fetched ' + bw + 'list ' + str(regexcount-orgregexcount) + ' REGEXES, ' + str(ipcount) + ' CIDRs, ' + str(domaincount) + ' DOMAINS and ' + str(asncount) + ' ASNs from ' + bw + '-file/list \"' + name + '\"')
                if (debug >= 2): log_info('Total ' + bw + 'list ' + str(len(regexlist)/3) + ' REGEXES, ' + str(len(iplist4) + len(iplist6)) + ' CIDRs, ' + str(len(domainlist)) + ' DOMAINS and ' + str(len(asnlist)) + ' ASNs in ' + bw + '-list')

                return addtolist

        except BaseException as err:
            log_err('Unable to open file \"' + name + '\" (' + orgid + ') - ' + str(err))

    return False


# Add CIDR to iplist
def add_cidr(iplist4, iplist6, entry, id):
    if entry.find(':') == -1:
        ipv6 = False
        iplist = iplist4
    else:
        ipv6 = True
        iplist = iplist6

    if entry.find('/') == -1: # Check if Single IP or CIDR already
        if ipv6:
            cidr = entry.lower() + '/128' # Single IPv6 Address
        else:
            cidr = entry + '/32' # Single IPv4 Address
    else:
        cidr = entry.lower()

    if iplist.has_key(cidr):
        if iplist[cidr].find(id) == -1:
            oldid = iplist[cidr].split('(')[1].split(')')[0].strip()
            try:
                iplist[cidr] = '\"' + cidr + '\" (' + str(oldid) + ', ' + str(id) + ')'
            except:
                log_err(name + ': Skipped invalid line/ip-address \"' + entry + '\"')
            return False
    else:
        try:
            iplist[cidr] = '\"' + cidr + '\" (' + str(id) + ')'
        except:
            log_err(name + ': Skipped invalid line/ip-address \"' + entry + '\"')
            return False

    return True


# Domain aggregator, removes subdomains if parent exists
def optimize_domlists(name, listname):
    log_info('\nUnduplicating/Optimizing \"' + listname + '\"')

    domlist = dom_sort(name.keys())

    # Remove all subdomains
    parent = '.invalid'
    undupped = set()
    for domain in domlist:
        if not domain.endswith(parent):
            undupped.add(domain)
            parent = '.' + domain.strip('.')
        else:
            if (debug >= 3): log_info('\"' + listname + '\": Removed domain \"' + domain + '\" redundant by parent \"' + parent.strip('.') + '\"')

    # New/Work dictionary
    new = dict()

    # Build new dictionary preserving id/category
    for domain in undupped:
        new[domain] = name[domain]

    # Some counting/stats
    before = len(name)
    after = len(new)
    count = after - before

    if (debug >= 2): log_info('\"' + listname + '\": Number of domains went from ' + str(before) + ' to ' + str(after) + ' (' + str(count) + ')')

    return new


# Unwhitelist IP's, if whitelist entry is not blacklisted, remove it.
def unwhite_ip(wlist, blist, listname):
    if not unwhitelist:
        return wlist

    if (debug >= 2): log_info('\nUn-Whitelisting IPs from ' + listname + ' NOT IMPLEMENTED!')
    # !!! TODO, placeholder
    return wlist


# Check if name exist in domain-list or is sub-domain in domain-list
def dom_find(name, dlist):
    testname = name
    while True:
        if testname in dlist:
            return testname
        elif testname.find('.') == -1:
            return False
        else:
            testname = testname[testname.find('.') + 1:]

    return False


# Unwhitelist domains, if whitelist entry is not blacklisted, remove it.
def unwhite_domain(wlist, blist):
    if not unwhitelist:
        return wlist

    if (debug >= 2): log_info('\nUn-Whitelisting domains from whitelist')

    new = dict()

    for entry in dom_sort(wlist.keys()):
        testname = entry
        notfound = True
        nomatchtld = True

        while True:
            if dom_find(testname, safewhitelist):
                if (debug >= 2): log_info('Skipped unwhitelisting \"' + entry + '\" due to being safelisted')
                break
            elif testname in blist:
                notfound = False
                if testname.find('.') == -1:
                    nomatchtld = False
                break
            elif testname.find('.') == -1:
                break
            else:
                testname = testname[testname.find('.') + 1:]

        legit = False
        if notfound and nomatchtld:
            if not check_regex(entry, 'black'):
                if (debug >= 3): log_info('Removed redundant white-listed domain \"' + entry + '\" (No blacklist hits)')
            else:
                legit = True

        if legit:
            new[entry] = wlist[entry]
        else:
            safeunwhitelist[entry] = 'Unwhitelist'

    before = len(wlist)
    after = len(new)
    count = before - after

    if (debug >= 2): log_info('Number of white-listed domains went from ' + str(before) + ' to ' + str(after) + ' (Unwhitelisted ' + str(count) + ')')

    return new


# Uncomplicate lists, removed whitelisted domains from blacklist
def uncomplicate_lists(whitelist, rwhitelist, blacklist, safelist):
    log_info('\nUncomplicating Domain black/whitelists')

    listw = dom_sort(whitelist.keys())
    listb = dom_sort(blacklist.keys())

    # Remove all 1-to-1/same whitelisted entries from blacklist
    # !!! We need logging on this !!!
    listb = dom_sort(list(set(listb).difference(listw)))

    # Create checklist for speed
    checklistb = '#'.join(listb) + '#'

    # loop through whitelist entries and find parented entries in blacklist to remove
    for domain in listw:
        if '.' + domain + '#' in checklistb:
            if (debug >= 3): log_info('Checking against \"' + domain + '\"')
            for found in filter(lambda x: x.endswith('.' + domain), listb):
                if not dom_find(found, safelist):
                   if (debug >= 3): log_info('Removed blacklist-entry \"' + found + '\" due to white-listed parent \"' + domain + '\"')
                   listb.remove(found)
                else:
                   if (debug >= 3): log_info('Preserved white-listed/safe-black-listed blacklist-entry \"' + found + '\" due to white-listed parent \"' + domain + '\"')

            checklistb = '#'.join(listb) + "#"
        #else:
        #    # Nothing to whitelist (breaks stuff, do not uncomment)
        #    if (debug >= 2): log_info('Removed whitelist-entry \"' + domain + '\", no blacklist hit')
        #    del whitelist[domain]

    # Remove blacklisted entries when matched against whitelist regex
    for i in range(0,len(rwhitelist)/3):
        checkregex = rwhitelist[i,1]
        if (debug >= 3): log_info('Checking against white-regex \"' + rwhitelist[i,2] + '\"')
        for found in filter(checkregex.search, listb):
            if not dom_find(found, safelist):
                listb.remove(found)
                if (debug >= 3): log_info('Removed \"' + found + '\" from blacklist, matched by white-regex \"' + rwhitelist[i,2] + '\"')
            else:
                if (debug >= 3): log_info('Preserved safe-black-listed \"' + found + '\" from blacklist, matched by white-regex \"' + rwhitelist[i,2] + '\"')

    # New/Work dictionary
    new = dict()

    # Build new dictionary preserving id/category
    for domain in listb:
        new[domain] = blacklist[domain]

    before = len(blacklist)
    after = len(new)
    count = after - before

    if (debug >= 2): log_info('Number of black-listed domains went from ' + str(before) + ' to ' + str(after) + ' (' + str(count) + ')')

    return new


# Remove excluded entries from domain-lists
def exclude_domlist(domlist, excludelist, listname):
    log_info('\nExcluding \"' + listname + '\"')

    newlist = deepcopy(domlist)
    checklist = '#'.join(newlist.keys()) + '#'

    for domain in dom_sort(excludelist.keys()):
        # Just the domain
        if domain in newlist:
            lname = newlist[domain]
            action = 'exclude'
            del newlist[domain]
            if (debug > 1): log_info('Removed excluded entry \"' + domain + '\" from \"' + listname + '\" (' + lname + ')')
            checklist = '#'.join(newlist.keys()) + '#'

        # All domains ending in excluded domain (Breaks too much, leave commented out)
        #if '.' + domain + "#" in checklist:
        #    for found in filter(lambda x: x.endswith('.' + domain), domlist.keys()):
        #        lname = newlist.pop(found, False)
        #        if (debug > 1): log_info('Removed excluded entry \"' + found + '\" (' + domain + ') from \"' + listname + '\" (' + lname + ')')
        #        checklist = '#'.join(newlist.keys()) + '#'
        #        deleted += 1

    before = len(domlist)
    after = len(newlist)
    deleted = before - after

    log_info('\"' + listname + '\" went from ' + str(before) + ' to ' + str(after) + ', after removing ' + str(deleted) + ' excluded entries')

    return newlist


# Uncomplicate IP lists, remove whitelisted IP's from blacklist
def uncomplicate_ip_lists(cwhitelist, cblacklist, listname):
    log_info('\nUncomplicating ' + listname + ' black/whitelists')

    listw = cwhitelist.keys()
    listb = cblacklist.keys()

    # Remove all 1-to-1/same whitelisted entries from blacklist
    # !!! We need logging on this !!!
    listb = dom_sort(list(set(listb).difference(listw)))

    # loop through blacklist entries and find whitelisted entries to remove
    for ip in listb:
        if ip in listw:
            if (debug >= 3): log_info('Removed blacklist-entry \"' + ip + '\" due to white-listed \"' + cwhitelist[ip] + '\"')
            listb.remove(ip)

    new = pytricia.PyTricia(128)

    # Build new dictionary preserving id/category
    for ip in listb:
        new[ip] = cblacklist[ip]

    before = len(cblacklist)
    after = len(new)
    count = after - before

    if (debug >= 2): log_info('Number of black-listed ' + listname + ' went from ' + str(before) + ' to ' + str(after) + ' (' + str(count) + ')')

    return new


# Remove entries from domains already matching by a regex
def unreg_lists(dlist, rlist, safelist, listname):
    log_info('\nUnregging \"' + listname + '\"')

    before = len(dlist)

    for i in range(0,len(rlist)/3):
        checkregex = rlist[i,1]
        if (debug >= 3): log_info('Checking against \"' + rlist[i,2] + '\"')
        for found in filter(checkregex.search, dlist):
            name = dlist[found]
            if not dom_find(name, safelist):
                del dlist[found]
                if (debug >= 3): log_info('Removed \"' + found + '\" from \"' + name + '\" matched by regex \"' + rlist[i,2] + '\"')
            else:
                if (debug >= 3): log_info('Preserved safelisted \"' + found + '\" from \"' + name + '\" matched by regex \"' + rlist[i,2] + '\"')

    after = len(dlist)
    count = after - before

    if (debug >= 2): log_info('Number of \"' + listname + '\" entries went from ' + str(before) + ' to ' + str(after) + ' (' + str(count) + ')')

    return dlist


# Save out generic/plain files
# !!! TEST - Needs try/except added
# !!! Maybe use dict and simplyfy in a loop for different lists
def plain_save(bw):
    log_info('Creating plain ' + bw + '-lists in ' + outputdir)

    if bw == 'white':
        domlist = whitelist
        asnlist = asnwhitelist
        iplist4 = cwhitelist4
        iplist6 = cwhitelist6
        rxlist = rwhitelist
    else:
        domlist = blacklist
        asnlist = asnblacklist
        iplist4 = cblacklist4
        iplist6 = cblacklist6
        rxlist = rblacklist

    if len(domlist) > 0:
        with open(outputdir + '/plain.' + bw + '.domain.list', 'w') as f:
            for domain in domlist.keys():
                f.write(domain)
                f.write('\n')

    if len(asnlist) > 0:
        with open(outputdir + '/plain.' + bw + '.asn.list', 'w') as f:
            for asn in asnlist.keys():
                f.write(asn)
                f.write('\n')

    if len(iplist4) > 0:
        with open(outputdir + '/plain.' + bw + '.ip4cidr.list', 'w') as f:
            for ip in iplist4.keys():
                f.write(ip)
                f.write('\n')

        with open(outputdir + '/plain.' + bw + '.ip4range.list', 'w') as f:
            for ip in iplist4.keys():
                f.write(IP(ip).strNormal(3))
                f.write('\n')

    if len(iplist6) > 0:
        with open(outputdir + '/plain.' + bw + '.ip6cidr.list', 'w') as f:
            for ip in iplist6.keys():
                f.write(ip)
                f.write('\n')

        with open(outputdir + '/plain.' + bw + '.ip6range.list', 'w') as f:
            for ip in iplist6.keys():
                f.write(IP(ip).strNormal(3))
                f.write('\n')

    if len(rxlist) > 0:
        with open(outputdir + '/plain.' + bw + '.regex.list', 'w') as f:
            for rx in range(0,len(rxlist)/3):
                f.write('/' + rxlist[rx,2] + '/')
                f.write('\n')

    if bw == 'black':
        adblock_save()
        dnsmasq_save()
        hosts_save()

    return True


# Save HostsFile
def hosts_save():
    log_info('Creating plain.hosts in ' + outputdir)
    with open(outputdir + '/plain.black.hosts.list', 'w') as f:
        for domain in blacklist.keys():
            f.write('0.0.0.0\t' + domain + '\n')
            f.write('::\t' + domain + '\n')
	
    with open(outputdir + '/plain.white.hosts.list', 'w') as f:
        for domain in whitelist.keys():
            f.write('0.0.0.0\t' + domain + '\n')
            f.write('::\t' + domain + '\n')

    return True


# Save adblock
def adblock_save():
    log_info('Creating adblock.txt in ' + outputdir)
    with open(outputdir + '/adblock.txt', 'w') as f:
        f.write('[Adblock Plus 1.1]\n')
        for domain in blacklist.keys():
            f.write('||' + domain + '^\n')
	
        for domain in whitelist.keys():
            f.write('@@||' + domain + '^\n')

    return True


# Save DNSMasq
def dnsmasq_save():
    log_info('Creating dnsmasq-servers.conf` in ' + outputdir)
    with open(outputdir + '/dnsmasq-servers.conf', 'w') as f:
        for domain in whitelist.keys():
            f.write('server=/' + domain + '/#\n')

        for domain in blacklist.keys():
            f.write('server=/' + domain + '/\n')

    return True


# Save lists to files
def write_out(whitefile, blackfile, generic):
    if whitefile:
        log_info('Saving processed whitelists to \"' + whitefile + '\"')
        try:
            with open(whitefile, 'w') as f:
                f.write('############################################\n')
                f.write('### ACCOMPLIST GENERATED WHITELIST       ###\n')
                f.write('### Version: ' + str(int(time.time())) + '                  ###\n')
                f.write('### Chris Buijs                          ###\n')
                f.write('### https://github.com/cbuijs/accomplist ###\n')
                f.write('############################################\n\n')
                if not generic:
                    f.write('### SAFELIST DOMAINS ###\n')
                    for line in dom_sort(safewhitelist.keys()):
                        f.write(line + '!\t' + safewhitelist[line])
                        f.write('\n')

                    f.write('### SAFEUNWHITELIST DOMAINS ###\n')
                    for line in dom_sort(safeunwhitelist.keys()):
                        f.write(line + '&\t' + safeunwhitelist[line])
                        f.write('\n')

                    f.write('### WHITELIST REGEXES ###\n')
                    for line in range(0,len(rwhitelist)/3):
                        f.write('/' + rwhitelist[line,2] + '/\t' + rwhitelist[line,0])
                        f.write('\n')

                f.write('### WHITELIST DOMAINS ###\n')
                for line in dom_sort(whitelist.keys()):
                    doit = False
                    if not generic:
                        if (line not in safewhitelist) and (line not in safeunwhitelist):
                            doit = True
                    else:
                        doit = True

                    if doit:
                        f.write(line + '\t' + whitelist[line])
                        f.write('\n')

                if not generic:
                    f.write('### WHITELIST ASN ###\n')
                    for a in sorted(asnwhitelist.keys()):
                        f.write(a + '\t' + asnwhitelist[a])
                        f.write('\n')

                f.write('### WHITELIST IPv4 ###\n')
                for a in cwhitelist4.keys():
                    f.write(a + '\t' + cwhitelist4[a].split('(')[1].split(')')[0].strip())
                    f.write('\n')
                    #f.write(IP(a).strNormal(3)) # Write out in range format x.x.x.x-y.y.y.y
                    #f.write('\n')

                f.write('### WHITELIST IPv6 ###\n')
                for a in cwhitelist6.keys():
                    f.write(a + '\t' + cwhitelist6[a].split('(')[1].split(')')[0].strip())
                    f.write('\n')

                f.write('### WHITELIST EOF ###\n')

        except BaseException as err:
            log_err('Unable to write to file \"' + whitefile + '\" (' + str(err) + ')')

    if blackfile:
        log_info('Saving processed blacklists to \"' + blackfile + '\"')
        try:
            with open(blackfile, 'w') as f:
                f.write('############################################\n')
                f.write('### ACCOMPLIST GENERATED BLACKLIST       ###\n')
                f.write('### Version: ' + str(int(time.time())) + '                  ###\n')
                f.write('### Chris Buijs                          ###\n')
                f.write('### https://github.com/cbuijs/accomplist ###\n')
                f.write('############################################\n\n')
                if not generic:
                    f.write('### SAFELIST DOMAINS ###\n')
                    for line in dom_sort(safeblacklist.keys()):
                        f.write(line + '!\t' + safeblacklist[line])
                        f.write('\n')

                    f.write('### BLACKLIST REGEXES ###\n')
                    for line in range(0,len(rblacklist)/3):
                        f.write('/' + rblacklist[line,2] + '/\t' + rblacklist[line,0])
                        f.write('\n')

                f.write('### BLACKLIST DOMAINS ###\n')
                for line in dom_sort(blacklist.keys()):
                    doit = False
                    if not generic:
                        if line not in safeblacklist:
                            doit = True
                    else:
                        doit = True

                    if doit:
                        f.write(line + '\t' + blacklist[line])
                        f.write('\n')

                if not generic:
                    f.write('### BLACKLIST ASN ###\n')
                    for a in sorted(asnblacklist.keys()):
                        f.write(a + '\t' + asnblacklist[a])
                        f.write('\n')

                f.write('### BLACKLIST IPv4 ###\n')
                for a in cblacklist4.keys():
                    f.write(a + '\t' + cblacklist4[a].split('(')[1].split(')')[0].strip())
                    f.write('\n')

                f.write('### BLACKLIST IPv6 ###\n')
                for a in cblacklist6.keys():
                    f.write(a + '\t' + cblacklist6[a].split('(')[1].split(')')[0].strip())
                    f.write('\n')

                f.write('### BLACKLIST EOF ###\n')

        except BaseException as err:
            log_err('Unable to write to file \"' + blackfile + '\" (' + str(err) + ')')

    return True


# Domain sort
def dom_sort(domlist):
    newdomlist = list()
    for y in sorted([x.split('.')[::-1] for x in domlist]):
        newdomlist.append('.'.join(y[::-1]))

    return newdomlist


# Aggregate IP list
def aggregate_ip(iplist, listname):
    log_info('\nAggregating \"' + listname + '\"')

    undupped = list(iplist.keys())

    if '#'.join(undupped).find(':') != -1:
        dictsize = 128
    else:
        dictsize = 32

    # Phase 1 - Removes child-subnets
    for ip in iplist.keys():
        bitmask = ip.split('/')[1]
        if not bitmask in ('32', '128'):
            try:
                children = iplist.children(ip)
                if children:
                   for child in children:
                        if child in undupped:
                            undupped.remove(child)
                            if (debug >= 3): log_info('Removed ' + child + ', already covered by ' + ip + ' in \"' + iplist[ip] + '\"')

            except BaseException as err:
                log_err(str(err))
                pass

    new = pytricia.PyTricia(dictsize)

    # Phase 2 - aggregate
    if aggregate:
        ipset = ip_sort(undupped)
        for ip in ipset:
            if ip in iplist:
                new[ip] = iplist[ip]
            else:
                new[ip] = '\"' + ip + '\" (Aggregated)'

    else:
        for ip in undupped:
            new[ip] = iplist[ip]
 
    before = len(iplist)
    after = len(new)
    count = after - before

    if (debug >= 2): log_info('\"' + listname + '\": Number of IP-Entries went from ' + str(before) + ' to ' + str(after) + ' (' + str(count) + ')')

    return new


# IP Sort/Aggregate
def ip_sort(iplist):
    ips = list()
    for ip in iplist:
        ips.append(IP(ip))

    ipset = IPSet(ips) # Here is the magic

    newlist = list()
    for ip in ipset:
        newlist.append(ip.strNormal(1))

    return newlist


# Check if file exists and return age (in seconds) if so
def file_exist(file):
    if file:
        try:
            if os.path.isfile(file):
                fstat = os.stat(file)
                fsize = fstat.st_size
                if fsize > 0:
                    fexists = True
                    mtime = int(fstat.st_mtime)
                    currenttime = int(time.time())
                    age = int(currenttime - mtime)
                    return age
        except:
            return False

    return False


# Make directory-structures
def make_dirs(dir):
    try:
        os.makedirs(dir)
    except BaseException as err:
        #log_err('Unable to create directory \"' + dir + '\" - ' + str(err))
        pass

    return True


## Main
if __name__ == "__main__":
    log_info('\n----- ACCOMPLIST STARTED -----\n')
 
    # Header/User-Agent to use when downloading lists, some sites block non-browser downloads
    headers = { 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36' }

    # Make sure dirs exists
    make_dirs(outputdir)
    make_dirs(workdir)

    log_info('SOURCES: ' + sources)
    log_info('OUTPUT DIR: ' + outputdir)
    log_info('WORK DIR: ' + workdir)

    # Load IPASN
    if ipasnfile:
        age = file_exist(ipasnfilecache)
        if age and age < maxlistage:
            log_info('Reading ASNs from cache \"' + ipasnfilecache + '\"')
            try:
                s = shelve.open(ipasnfilecache, flag = 'r', protocol = 2)
                asnip = s['asnip']
                s.close()

            except BaseException as err:
                log_err('ERROR: Unable to open/read file \"' + ipasnfile + '\" - ' + str(err))

        elif file_exist(ipasnfile):
            log_info('Reading IPASN file from \"' + ipasnfile + '\"')
            try:
                with open(ipasnfile, 'r') as f:
                    for line in f:
                        entry = line.strip()
                        if not (entry.startswith("#")) and not (len(entry) == 0):
                            try:
                                ip, asn = regex.split('\s+', entry)

                                lst = list()
                                if asn in asnip:
                                    lst = asnip[asn]

                                lst.append(ip)
                                asnip[asn] = lst

                            except BaseException as err:
                                log_err('Invalid line in \"' + ipasnfile + '\": ' + entry + ' - ' + str(err))
                                pass

            except BaseException as err:
                log_err('Unable to read from file \"' + ipasnfile + '\": ' + str(err))
                ipasnfile = False

            # Sort/Aggregate
            log_info('Sorting/Aggregating ' + str(len(asnip)) + ' IPASNs')
            before = 0
            after = 0
            for asn in asnip.keys():
                lst = asnip[asn]
                before = before + len(lst)
                asnip[asn] = ip_sort(lst)
                after = after + len(asnip[asn])
            log_info('Sorted/Aggregated IPASNs from ' + str(before) + ' to ' + str(after) + ' CIDR entries')

            if ipasnoutfile:
                log_info('Writing aggregated ASN entries to \"' + ipasnoutfile + '\"')
                try:
                    with open(ipasnoutfile, 'w') as f:
                        for asn in sorted(asnip.keys(), key = int):
                            for ip in asnip[asn]:
                                f.write(ip + '\t' + asn + '\n')

                except BaseException as err:
                    log_err('Cannot open/write to \"' + ipasnoutfile + '\" - ' + str(err))

            if ipasnfilecache:
                log_info('Shelving ASN entries to \"' + ipasnfilecache + '\"')
                try:
                    s = shelve.open(ipasnfilecache, flag = 'n', protocol = 2)
                    s['asnip'] = asnip
                    s.close()

                except BaseException as err:
                    log_err('Cannot Shelve ASN entries to \"' + ipasnfilecache + '\" - ' + str(err))

        log_info(str(len(asnip)) + ' IPASN Entries')


    # Get top-level-domains
    if tldfile:
        tldlist.clear()
        age = file_exist(tldfile)
        if not age or age > maxlistage:
            log_info('Downloading IANA TLD list to \"' + tldfile + '\"')
            r = requests.get('https://data.iana.org/TLD/tlds-alpha-by-domain.txt', headers=headers, allow_redirects=True)
            if r.status_code == 200:
                try:
                    with open(tldfile, 'w') as f:
                        f.write(r.text.encode('ascii', 'ignore').replace('\r', '').lower())

                except BaseException as err:
                    log_err('Unable to write to file \"' + tldfile + '\": ' + str(err))
                    tldfile = False

        if tldfile:
            log_info('Fetching TLD list from \"' + tldfile + '\"')
            try:
                with open(tldfile, 'r') as f:
                    for line in f:
                        entry = line.strip()
                        if not (entry.startswith("#")) and not (len(entry) == 0):
                            tldlist[entry] = True

            except BaseException as err:
                log_err('Unable to read from file \"' + tldfile + '\": ' + str(err))
                tldfile = False

            if tldfile:
                if rfc2606:
                    tldlist['example'] = True
                    tldlist['invalid'] = True
                    tldlist['localhost'] = True
                    tldlist['test'] = True

                if notinternet:
                    tldlist['onion'] = True

                if intranet:
                    tldlist['corp'] = True
                    tldlist['home'] = True
                    tldlist['host'] = True
                    tldlist['lan'] = True
                    tldlist['local'] = True
                    tldlist['localdomain'] = True
                    tldlist['router'] = True
                    tldlist['workgroup'] = True

            log_info('fetched ' + str(len(tldlist)) +  ' TLDs')


    if fileregexlist:
            log_info('Fetching list-regexes from \"' + fileregexlist + '\"')
            try:
                with open(fileregexlist, 'r') as f:
                    for line in f:
                        entry = line.strip()
                        if not (entry.startswith("#")) and not (len(entry) == 0):
                            elements = entry.split('\t')
                            if len(elements) > 1:
                                name = elements[0].strip().upper()
                                if (debug >= 2): log_info('Fetching file-regex \"@' + name + '\"')
                                fileregex[name] = elements[1]
                            else:
                                log_err('Invalid list-regex entry: \"' + entry + '\"')

            except BaseException as err:
                log_err('Unable to read from file \"' + fileregexlist + '\": ' + str(err))
                tldfile = False

    # Read Lists
    readblack = True
    readwhite = True

    age = file_exist(whitesave)
    if age and age < maxlistage:
        log_info('Using White-Savelist, not expired yet (' + str(age) + '/' + str(maxlistage) + ')')
        read_lists('saved-whitelist', whitesave, rwhitelist, cwhitelist4, cwhitelist6, whitelist, asnwhitelist, safewhitelist, safeunwhitelist, True, 'white')
        readwhite = False

    age = file_exist(blacksave)
    if age and age < maxlistage:
        log_info('Using Black-Savelist, not expired yet (' + str(age) + '/' + str(maxlistage) + ')')
        read_lists('saved-blacklist', blacksave, rblacklist, cblacklist4, cblacklist6, blacklist, asnblacklist, safeblacklist, False, True, 'black')
        readblack = False

    addtoblack = dict()
    addtowhite = dict()

    try:
        with open(sources, 'r') as f:
            for line in f:
                entry = line.strip().replace('\r', '')
                if not (entry.startswith("#")) and not (len(entry) == 0):
                    element = entry.split('\t')
                    if len(element) > 2:
                        id = element[0]
                        bw = element[1].lower()

                        log_info('\n----- ' + id.upper() + ' -----')

                        if (bw == 'black' and readblack) or (bw == 'white' and readwhite) or (bw == 'exclude' and (readwhite or readblack)):
                            source = element[2]
                            downloadfile = False
                            listfile = False
                            force = False
                            url = False

                            if source.startswith('http://') or source.startswith('https://'):
                                url = source
                                if (debug >= 2): log_info('Source for \"' + id + '\" is an URL: \"' + url + '\"')
                            else:
                                if (debug >= 2): log_info('Source for \"' + id + '\" is a FILE: \"' + source + '\"')
                                
                            if source:
                                if len(element) > 3:
                                    listfile = element[3]
                                else:
                                    listfile = '/etc/unbound/' + id.strip('.').lower() + ".list"

                                if workdir:
                                    listfile = workdir + '/' + listfile.split('/')[-1]
    
                                if len(element) > 4:
                                    filettl = int(element[4])
                                else:
                                    filettl = maxlistage
    
                                fregex = defaultfregex
                                if len(element) > 5:
                                    r = element[5]
                                    if r.startswith('@'):
                                        r = r.split('@')[1].upper().strip()
                                        if r in fileregex:
                                            fregex = fileregex[r]
                                            if (debug >= 3): log_info('Using \"@' + r + '\" regex/filter for \"' + id + '\" (' + fregex + ')')
                                        else:
                                            log_err('Regex \"@' + r + '\" does not exist in \"' + fileregexlist + '\" using default \"' + defaultfregex +'\"')
                                    
                                    elif r.find('(?P<') == -1:
                                        log_err('Regex \"' + r + '\" does not contain placeholder (e.g: \"(?P< ... )\")')
                                    else:
                                        fregex = r

                                exclude = regex.compile(defaultexclude, regex.I)
                                if len(element) > 6:
                                    r = element[6]
                                    if r.startswith('@'):
                                        r = r.split('@')[1].upper().strip()
                                        if r in fileregex:
                                            exclude = regex.compile(fileregex[r], regex.I)
                                            if (debug >= 3): log_info('Using \"@' + r + '\" exclude regex/filter for \"' + id + '\" (' + r + ')')
                                        else:
                                            log_err('Regex \"@' + r + '\" does not exist in \"' + fileregexlist + '\" using default \"' + defaultexclude +'\"')
                                    else:
                                        exclude = regex.compile(r, regex.I)

                                if url:
                                    age = file_exist(listfile)
                                    if not age or age > filettl or force:
                                        downloadfile = listfile + '.download'
                                        log_info('Downloading \"' + id + '\" from \"' + url + '\" to \"' + downloadfile + '\"')
                                        try:
                                            r = requests.get(url, headers=headers, allow_redirects=True)
                                            if r.status_code == 200:
                                                try:
                                                    with open(downloadfile, 'w') as f:
                                                        f.write(r.text.encode('ascii', 'ignore').replace('\r', '').strip().lower())

                                                except BaseException as err:
                                                    log_err('Unable to write to file \"' + downloadfile + '\": ' + str(err))

                                            else:
                                                log_err('Error during downloading from \"' + url + '\"')

                                        except BaseException as err:
                                            log_err('Error downloading from \"' + url + '\": ' + str(err))

                                    else:
                                        log_info('Skipped download \"' + id + '\" previous list \"' + listfile + '\" is only ' + str(age) + ' seconds old')
                                        source = listfile

                                if url and downloadfile:
                                    sourcefile = downloadfile
                                else:
                                    sourcefile = source

                                if file_exist(sourcefile) >= 0:
                                    if sourcefile != listfile:
                                        try:
                                            log_info('Creating \"' + id + '\" file \"' + listfile + '\" from \"' + sourcefile + '\"')
                                            with open(sourcefile, 'r') as f:
                                                try:
                                                    with open(listfile, 'w') as g:
                                                        for line in f:
                                                            line = line.replace('\r', '').lower().strip()
                                                            if line and len(line) >0:
                                                                if not exclude.match(line):
                                                                    matchentry = regex.match(fregex, line, regex.I)
                                                                    if matchentry:
                                                                        for placeholder in ['asn', 'domain', 'entry', 'ip', 'line', 'regex']:
                                                                            try:
                                                                                entry = matchentry.group(placeholder)
                                                                            except:
                                                                                entry = False

                                                                            if entry and len(entry) > 0:
                                                                                if not exclude.match(entry):
                                                                                    # !!! To do: use placholder to pre-process/validate/error-check type of entry via regex
                                                                                    g.write(entry)
                                                                                    g.write('\n')
                                                                                else:
                                                                                    if (debug >= 3): log_info(id +': Skipping excluded entry \"' + line + '\" (' + entry + ')')

                                                                    else:
                                                                        if (debug >= 3): log_info(id +': Skipping non-matched line \"' + line + '\"')

                                                                else:
                                                                    if (debug >= 3): log_info(id +': Skipping excluded line \"' + line + '\"')

                                                except BaseException as err:
                                                    log_err('Unable to write to file \"' + listfile + '\" (' + str(err) + ')')

                                        except BaseException as err:
                                            log_err('Unable to read source-file \"' + sourcefile + '\" (' + str(err) + ')')

                                    else:
                                        log_info('Skipped processing of \"' + id + '\", source-file \"' + sourcefile + '\" same as list-file')

                                else:
                                    log_info('Skipped \"' + id + '\", source-file \"' + sourcefile + '\" does not exist')


                            if file_exist(listfile) >= 0:
                                if bw == 'black':
                                     a2b = dict()
                                     a2b = read_lists(id, listfile, rblacklist, cblacklist4, cblacklist6, blacklist, asnblacklist, safeblacklist, False, force, bw)
                                     if a2b:
                                         for i in a2b:
                                             addtoblack[i] = a2b[i]
                                elif bw == 'white':
                                    read_lists(id, listfile, rwhitelist, cwhitelist4, cblacklist6, whitelist, asnwhitelist, safewhitelist, safeunwhitelist, force, bw)
                                elif bw == 'exclude':
                                    excount = 0
                                    try:
                                        with open(listfile, 'r') as f:
                                            for line in f:
                                                elements = line.strip().replace('\r', '').split('\t')
                                                entry = elements[0]
                                                if (len(entry) > 0) and isdomain.match(entry):
                                                    if len(elements)>1:
                                                        action = elements[1]
                                                    else:
                                                        action = 'exclude'

                                                    if action == 'black':
                                                        addtoblack[entry] = id
                                                    elif action == 'white':
                                                        addtowhite[entry] = id
                                                    excludelist[entry] = id
                                                    excount += 1

                                        log_info('Fetched ' + str(excount) + ' exclude entries from \"' + listfile + '\" (' + id + ')')

                                    except BaseException as err:
                                        log_err('Unable to read list-file \"' + listfile + '\" (' + str(err) + ')')

                                else:
                                    log_err('Unknow type \"' + bw + '\" for file \"' + listfile + '\"')
                            else:
                                log_err('Cannot open \"' + listfile + '\"')
                        else:
                            log_info('Skipping ' + bw + 'list \"' + id + '\", using savelist')
                    else:
                        log_err('Not enough arguments: \"' + entry + '\"')

    except BaseException as err:
        log_err('Unable to open file \"' + sources + '\": ' + str(err))

    log_info('\n----- OPTIMIZING PHASE -----')

    # Excluding domains, first thing to do on "dirty" lists
    if excludelist and (readblack or readwhite):
        # Optimize excludelist
        excludelist = optimize_domlists(excludelist, 'ExcludeDoms')

        # Remove exclude entries from lists
        whitelist = exclude_domlist(whitelist, excludelist, 'WhiteDoms')
        blacklist = exclude_domlist(blacklist, excludelist, 'BlackDoms')
        
        # Add exclusion entries when requested
        whitelist = add_exclusion(whitelist, addtowhite, safewhitelist, 'WhiteDoms')
        blacklist = add_exclusion(blacklist, addtoblack, safeblacklist, 'BlackDoms')

    # Optimize/Aggregate white domain lists (remove sub-domains is parent exists and entries matchin regex)
    if readwhite:
        whitelist = optimize_domlists(whitelist, 'WhiteDoms')
        cwhitelist4 = aggregate_ip(cwhitelist4, 'WhiteIP4s')
        cwhitelist6 = aggregate_ip(cwhitelist6, 'WhiteIP6s')
        #write_out(genericwhitesave, False, True)
        plain_save('white')
        whitelist = unreg_lists(whitelist, rwhitelist, safewhitelist, 'WhiteDoms')

    # Optimize/Aggregate black domain lists (remove sub-domains is parent exists and entries matchin regex)
    if readblack:
        blacklist = optimize_domlists(blacklist, 'BlackDoms')
        cblacklist4 = aggregate_ip(cblacklist4, 'BlackIP4s')
        cblacklist6 = aggregate_ip(cblacklist6, 'BlackIP6s')
        #write_out(False, genericblacksave, True)
        plain_save('black')
        blacklist = unreg_lists(blacklist, rblacklist, safeblacklist, 'BlackDoms')

    # Remove whitelisted entries from blacklist
    if readblack or readwhite:
        blacklist = uncomplicate_lists(whitelist, rwhitelist, blacklist, safeblacklist)
        cblacklist4 = uncomplicate_ip_lists(cwhitelist4, cblacklist4, 'IPv4')
        cblacklist6 = uncomplicate_ip_lists(cwhitelist6, cblacklist6, 'IPv6')
        whitelist = unwhite_domain(whitelist, blacklist)
        cwhitelist4 = unwhite_ip(cwhitelist4, cblacklist4, 'IPv4 List')
        cwhitelist6 = unwhite_ip(cwhitelist6, cblacklist6, 'IPv6 List')

    log_info('\n----- GRAND TOTAL -----')

    # Reporting
    regexcount = str(len(rwhitelist)/3)
    ipcount = str(len(cwhitelist4) + len(cwhitelist6))
    domaincount = str(len(whitelist))
    asncount = str(len(asnwhitelist))
    log_info('WhiteList Totals: ' + regexcount + ' REGEXES, ' + ipcount + ' IPs/CIDRs, ' + domaincount + ' DOMAINS and ' + asncount + ' ASNs')

    regexcount = str(len(rblacklist)/3)
    ipcount = str(len(cblacklist4) + len(cblacklist6))
    domaincount = str(len(blacklist))
    asncount = str(len(asnblacklist))
    log_info('BlackList Totals: ' + regexcount + ' REGEXES, ' + ipcount + ' IPs/CIDRs, ' + domaincount + ' DOMAINS and ' + asncount + ' ASNs')

    log_info('\n----- SAVE LISTS -----')

    # Save processed list for distribution
    write_out(whitesave, blacksave, False)

    log_info('\n----- ACCOMPLIST Finished -----\n')

    sys.exit(0)

##########################################################################################
# <EOF>
