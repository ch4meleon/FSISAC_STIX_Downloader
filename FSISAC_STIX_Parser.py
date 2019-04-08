#!/usr/bin/env python

"""
FSISAC STIX Parser (FSISAC_STIX_Parser.py)
Written by Michael Lim (ch4meleon@protonmail.com)

"""

import os
import sys
import socket
import types
import collections
import json
import re
import io
import urllib2
import dateutil
import datetime
import time
import pytz
import pprint
import getpass
import csv
import iocextract
import dicttoxml
import libtaxii as t
import libtaxii.messages_11 as tm11
import libtaxii.clients as tc
import lxml.etree
from stix.core import STIXPackage
from StringIO import StringIO
from urlparse import urlparse
from optparse import OptionParser
from optparse import BadOptionError
from optparse import AmbiguousOptionError
from stix.core import STIXPackage, STIXHeader
from stix.utils.parser import EntityParser
from stix.common import vocabs
from stix.common.vocabs import VocabString
from stix.common.vocabs import IndicatorType
from xml.etree.ElementTree import XML, XMLParser, tostring, TreeBuilder


class FSISAC_STIX_Parser:
    def __init__(self):
        pass

    """ Extract observables from STIX. Used by extractObservables function """
    def extractObservable(self, obs, values):
        typ = obs["properties"]["xsi:type"]

        val = None
        if typ == "AddressObjectType":            
            # Handle if Address_Value is a plain string or one with datatype
            if isinstance(obs["properties"]["address_value"], basestring):
                val = obs["properties"]["address_value"]
            elif 'value' in obs["properties"]["address_value"]:
                val = obs["properties"]["address_value"]["value"]
        elif typ == "URIObjectType" or typ == "DomainNameObjectType" or typ == "HostnameObjectType":
            val = obs["properties"]["value"]
            if 'value' in val:
                val = obs["properties"]["value"]["value"]
            else:
                val = obs["properties"]["value"]
        elif typ == "UserAccountObjectType":
            val = obs["properties"]["username"]
        elif typ == "FileObjectType":
            val = []
            theList = obs["properties"]["hashes"][0]
            if len(theList['simple_hash_value']) > 2:
                val.append( theList['simple_hash_value'] ) 
            else:
                val.append( obs["properties"]["hashes"][0]['simple_hash_value']['value'] )
            
        if val:
            if ( not isinstance(val, basestring) ) and isinstance(val, collections.Iterable):
                for addr in val:
                    values.append( addr )
            else:
                values.append( val )
        else:
            if args[0].strict:
                raise Exception("Encountered unsupported CybOX observable type: " + typ)
            else:
                print >> sys.stderr, "Encountered unsupported CybOX observable type: " + typ + ", ignoring..."
            
            
    """ Extract observables from STIX """
    def extractObservables(self, indicators):
        values = []
        STIX_TYPE = ""

        for indicator in indicators:
            
            # Check if we were passed a list of indicators, or observables
            obs = indicator

            # print("===========================")
            # print("OBS:")
            # pprint.pprint(obs)
            # print("===========================")

            # print ("")

            # print("===========================")
            # print("INDICATOR:")
            # pprint.pprint(indicator)
            # print("===========================")

            if "observable" in indicator:
                obs = indicator["observable"]

            ### To handle FSISAC which put data in 'description' ###
            IS_FSISAC = False

            if "observable" in indicator:
                tmp_obs = indicator['observable']
                if 'idref' in tmp_obs:
                    if "fsisac" in tmp_obs['idref']:
                        IS_FSISAC = True

            if IS_FSISAC == True:
                STIX_TYPE = "type1"
                # print "FOUND FSISAC"

                #iocs = dict()
                #title = "TESTING"
                #iocs = {'title' : '', 'domain':[], 'ip':[], 'email':[], 'hash':[], 'url':[], 'hash':[], 'yara':[], 'other' : []}

                title = indicator['title']
                description = indicator["description"]

                iocs = self.parse_indicators_from_description_string(description, title)
                return (STIX_TYPE, iocs)

                sys.exit(0)

                #return iocs

            else:
                try:
                    STIX_TYPE = "other"

                    if 'object' in obs:
                        self.extractObservable(obs["object"], values)

                    elif 'observable_composition' in obs:
                        for observable in obs["observable_composition"]["observables"]:
                            if 'object' in observable:
                                self.extractObservable(observable["object"], values )

                    else:
                        print "EXCEPTION999"
                        raise Exception("Unknown Object Type!! Please Investigate")

                        # if IS_FSISAC == True:
                        #     print "FOUND FSISAC"

                        #     description = indicator["description"]
                        #     title = indicator["title"]

                        #     print "-" * 100
                        #     print "INDICATOR:"
                        #     print indicator
                        #     print "-" * 100

                        #     raise Exception("BYEBYEBYE")

                        #     iocs = self.parse_indicators_from_description_string(description)
                        #     iocs['title'] = title

                        #     # return iocs

                        # else:
                        #     raise Exception("Unknown Object Type!! Please Investigate")

                except:
                    print >> sys.stderr, "Could not handle observable/indicator:\n"
                    pprint.pprint( indicator, sys.stderr )
                    raise

            # print "=" * 100
            # print "extractObservables - values:"
            # print values
            # print "=" * 100

        return (STIX_TYPE, values)


    # Processes a STIX package dictionary
    def process_stix_dict(self, stix_dict):
        iocs = {'title' : '', 'domain':[], 'ip':[], 'email':[], 'hash':[], 'url':[], 'hash':[], 'yara':[], 'other' : []}

        result = []
        key = ""
        value = ""

        """ Retrieve title """
        try:
            title = stix_dict['observables']['observables'][0]['title']
            iocs['title'] = title

        except:
            # Do something if necessary
            pass

        if "observables" in stix_dict:
            result.extend(self.extractObservables(stix_dict["observables"]["observables"]))

        if "indicators" in stix_dict:
            result.extend(self.extractObservables(stix_dict["indicators"]))

        # print "=" * 100
        # print "VALUES2"
        # print result
        # print "=" * 100

        stix_type = result[0]

        if stix_type == "type1": # No need to process, already in IOC dict format
            return result[1]

        values = result[1]

        if len(values) > 0:
            for item in values:
                try:
                    ## send data to stdout if needed and/or save to a simple text file.
                    if re.match("^(http|https)", item):
                        u = urlparse(item)
                        # print 'Web Site: %s | Path: %s' % ( u.netloc, u.path )
                        iocs['url'].append(u.netloc)

                    elif re.match("[^@]+@[^@]+\.[^@]+", item ):
                        # print 'Email Address: %s' % ( item )
                        iocs['email'].append(item)

                    elif re.match("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", item):
                        # print 'IP Address: %s' % ( item )
                        iocs['ip'].append(item)

                    elif re.match("^:", item):
                        item = item[2:]
                        myitem = 'http://' + item
                        d = urlparse(myitem)
                        item = d.netloc
                        # print 'Domain: %s' % ( d.netloc )
                        iocs['domain'].append(d.netloc)

                    elif re.match("^(([a-z0-9]\-*[a-z0-9]*){1,63}\.?){1,255}$", item):
                        # print 'Domain: %s' % ( item )
                        iocs['domain'].append(item)                    

                    elif re.match("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}$", item):
                        data = item.split(":")
                        #print data
                        # print 'IP Address: %s | Dest Port: %s' % ( data[0], data[1] )
                        iocs['ip'].append(data[0])

                    else:
                        # print 'Indicator: %s' % ( item )
                        iocs['other'].append(item)

                except ValueError:
                    print >> sys.stderr, "Could not parse values.."
                    print >> sys.stderr, item
                    raise

        # print "END" * 100
        # print iocs
        # print "END" * 100
                    
        return iocs


    """ Extract IOC(s) from the DESCRIPTION string (string type) """
    def parse_indicators_from_description_string(self, description_string, title):

        # print type(description_string)

        iocs = {'title' : title, 'domain':[], 'ip':[], 'email':[], 'hash':[], 'url':[], 'hash':[], 'yara':[], 'other' : []}
        on9strings = {'[.]':'.', 'hxxp':'http', '[@]':'@'}

        # Convert the first STIXPackage dictionary into another STIXPackage via the from_dict() method.      
        # Pattern for domain / email and IP addresses
        raw_iocs = re.findall(r'[a-zA-Z0-9-\.]*\[\.?\@?\][a-zA-Z0-9-\.\[\.\@\]]*[-a-zA-Z0-9@:%_\+.~#?&//=]*', description_string)

        # print(len(raw_iocs))

        # for i in range(len(raw_iocs)):
        #     # Replace the on9 strings
        #     for on9string in on9strings:
        #         raw_iocs[i] = raw_iocs[i].replace(on9string, on9strings[on9string])
                
        #     # Import those IOCs into the array.
        #     if re.match(r'.*[@]+', raw_iocs[i]):
        #         iocs['email'].append(raw_iocs[i])

        #     elif re.match(r'.*[//].*', raw_iocs[i]):
        #         iocs['url'].append(raw_iocs[i])

        #     elif re.match(r'.*[a-zA-Z]', raw_iocs[i]):
        #         iocs['domain'].append(raw_iocs[i])

        # # Extract hashes by their plugin
        # for hash_extracted in iocextract.extract_hashes(description_string):
        #     iocs['hash'].append(hash_extracted)

        # # Extract Yara rule
        # for yara_extracted in iocextract.extract_yara_rules(description_string):
        #     iocs['yara'].append(yara_extracted)

        # # Extract IP
        # for ip_extracted in iocextract.extract_ips(description_string, refang=True):
        #     iocs['ip'].append(ip_extracted)

        for i in range(len(raw_iocs)):
            # Replace the on9 strings
            for on9string in on9strings:
                raw_iocs[i] = raw_iocs[i].replace(on9string, on9strings[on9string])
                
            # Import those IOCs into the array.
            if re.match(r'.*[@]+', raw_iocs[i]):
                iocs['email'].append(raw_iocs[i])
                iocs['email'] = list(set(iocs['email']))

            elif re.match(r'.*[//].*', raw_iocs[i]):
                iocs['url'].append(raw_iocs[i])
                iocs['url'] = list(set(iocs['url']))

            elif re.match(r'.*[a-zA-Z]', raw_iocs[i]):
                if re.match("^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$", raw_iocs[i]):
                    iocs['domain'].append(raw_iocs[i])
                    iocs['domain'] = list(set(iocs['domain']))

        # Extract hashes by their plugin
        for hash_extracted in iocextract.extract_hashes(description_string):
            iocs['hash'].append(hash_extracted)
            iocs['hash'] = list(set(iocs['hash']))

        # Extract Yara rule
        for yara_extracted in iocextract.extract_yara_rules(description_string):
            iocs['yara'].append(yara_extracted)
            iocs['yara'] = list(set(iocs['yara']))

        # Extract IP
        for ip_extracted in iocextract.extract_ips(description_string, refang=True):
            # Use regex to validate the IP format
            if re.match(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", ip_extracted):
                iocs['ip'].append(ip_extracted)
                iocs['ip'] = list(set(iocs['ip']))        

        # for key in iocs:
        #     for item in iocs[key]:
        #         print(key + ":" + item)

        return iocs


    """ Extract IOC(s) from the DESCRIPTION section in FSISAC Stix """
    def _parse_indicators_from_stix_description(self, xml_content):
        iocs = {'title' : '', 'domain':[], 'ip':[], 'email':[], 'hash':[], 'url':[], 'hash':[], 'yara':[], 'other' : []}
        on9strings = {'[.]':'.', 'hxxp':'http', '[@]':'@'}

        # Parse input file
        stix_package = STIXPackage.from_xml(xml_content)

        # Convert STIXPackage to a Python 
        stix_dict = stix_package.to_dict()

        # Extract description from the indicator (suitable for indicator only)
        # print "-" * 100
        # print stix_dict
        # print "-" * 100

        description = stix_dict["indicators"][0]["description"]

        # Extract title
        title = stix_dict["indicators"][0]["title"]
        iocs['title'] = [title]

        # Convert the first STIXPackage dictionary into another STIXPackage via the from_dict() method.      
        # Pattern for domain / email and IP addresses
        raw_iocs = re.findall(r'[a-zA-Z0-9-\.]*\[\.?\@?\][a-zA-Z0-9-\.\[\.\@\]]*[-a-zA-Z0-9@:%_\+.~#?&//=]*', description)

        # print(len(raw_iocs))

        for i in range(len(raw_iocs)):
            # Replace the on9 strings
            for on9string in on9strings:
                raw_iocs[i] = raw_iocs[i].replace(on9string, on9strings[on9string])
                
            # Import those IOCs into the array.
            if re.match(r'.*[@]+', raw_iocs[i]):
                iocs['email'].append(raw_iocs[i])
                iocs['email'] = list(set(iocs['email']))

            elif re.match(r'.*[//].*', raw_iocs[i]):
                iocs['url'].append(raw_iocs[i])
                iocs['url'] = list(set(iocs['url']))

            elif re.match(r'.*[a-zA-Z]', raw_iocs[i]):
                if re.match("^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$", raw_iocs[i]):
                    iocs['domain'].append(raw_iocs[i])
                    iocs['domain'] = list(set(iocs['domain']))

        # Extract hashes by their plugin
        for hash_extracted in iocextract.extract_hashes(description):
            iocs['hash'].append(hash_extracted)
            iocs['hash'] = list(set(iocs['hash']))

        # Extract Yara rule
        for yara_extracted in iocextract.extract_yara_rules(description):
            iocs['yara'].append(yara_extracted)
            iocs['yara'] = list(set(iocs['yara']))

        # Extract IP
        for ip_extracted in iocextract.extract_ips(description, refang=True):
            # Use regex to validate the IP format
            if re.match(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", ip_extracted):
                iocs['ip'].append(ip_extracted)
                iocs['ip'] = list(set(iocs['ip']))

        # for key in iocs:
        #     for item in iocs[key]:
        #         print(key + ":" + item)

        return iocs


    """ Convert iocs dict to JSON """
    def convert_to_json(self, iocs):
        result = {}

        # Get title first
        title = ""

        for ioc in iocs:
            if ioc == "title":
                try:
                    title = iocs[ioc]
                except:
                    pass

        l = []
        for ioc in iocs:
            if ioc != "title":
                for item in iocs[ioc]:
                    new_dict_item = dict()
                    new_dict_item['title'] = title
                    new_dict_item['type'] = ioc
                    new_dict_item['value'] = item
                    l.append(new_dict_item)

        result = json.dumps({'IOCS' : l})

        return result


    """ Parse by stix file """
    def parse_stix_file(self, filename):
        stix_package = STIXPackage.from_xml(filename)
        stixParser = FSISAC_STIX_Parser()

        iocs = stixParser.process_stix_dict(stix_package.to_dict())

        j = stixParser.convert_to_json(iocs)

        return j


def test():
    # Process a XML file on disk        
    stix_package = STIXPackage.from_xml(sys.argv[1])

    stixParser = FSISAC_STIX_Parser()
    iocs = stixParser.process_stix_dict(stix_package.to_dict())

    j = stixParser.convert_to_json(iocs)
    print j
    

def test2():
    content = open(sys.argv[1]).read()
    sio = StringIO(content)

    stixParser = FSISAC_STIX_Parser()
    iocs = stixParser._parse_indicators_from_stix_description(sio)

    j = stixParser.convert_to_json(iocs)

    parsed = json.loads(j)
    print(json.dumps(parsed, indent=4, sort_keys=True))


def test3():
    from glob import glob

    stixParser = FSISAC_STIX_Parser()

    stix_files = glob("tests/*.xml")
    for s in stix_files:
        print "Processing file...(%s)" % s
        r = stixParser.parse_stix_file(s)
        print (r)
        print ""


if __name__ == "__main__":
    test3()
