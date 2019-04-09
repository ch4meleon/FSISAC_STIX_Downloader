#!/usr/bin/env python

"""
FSISAC STIX Downloader (FSISAC_STIX_Downloader.py)
Written by Michael Lim (ch4meleon@protonmail.com)

"""

import os
import sys
import time
import datetime
import random
import traceback
import pytz
import libtaxii as t
import libtaxii.clients as tc
import libtaxii.messages_11 as tm11
import hashlib
from libtaxii.common import gen_filename
from libtaxii.constants import *
from configobj import ConfigObj
from FSISAC_STIX_Parser import *
from glob import glob


""" Load FSISAC configuration file """
config = ConfigObj("fsisac.conf")

STIX_DOWNLOADED_PATH = 'stix_files' # Directory to write the returned STIX packages to.
FSISAC_USERNAME = config["FSISAC_USERNAME"]
FSISAC_PASSWORD = config["FSISAC_PASSWORD"]
FSISAC_KEY = config["FSISAC_KEY"]
FSISAC_CERT = config["FSISAC_CERT"]
FSISAC_STIX_DOWNLOADED_PATH = config["FSISAC_STIX_DOWNLOADED_PATH"]
DOWNLOAD_INTERVAL_MINUTE = config["DOWNLOAD_INTERVAL_MINUTE"]
FSISAC_JSON_OUTPUT_PATH = config['FSISAC_JSON_OUTPUT_PATH']


def print_banner():
    banner = """
 ______ _____ _____  _____         _____    _____ _______ _______   __  _____                      _                 _           
|  ____/ ____|_   _|/ ____|  /\   / ____|  / ____|__   __|_   _\ \ / / |  __ \                    | |               | |          
| |__ | (___   | | | (___   /  \ | |      | (___    | |    | |  \ V /  | |  | | _____      ___ __ | | ___   __ _  __| | ___ _ __ 
|  __| \___ \  | |  \___ \ / /\ \| |       \___ \   | |    | |   > <   | |  | |/ _ \ \ /\ / / '_ \| |/ _ \ / _` |/ _` |/ _ \ '__|
| |    ____) |_| |_ ____) / ____ \ |____   ____) |  | |   _| |_ / . \  | |__| | (_) \ V  V /| | | | | (_) | (_| | (_| |  __/ |   
|_|   |_____/|_____|_____/_/    \_\_____| |_____/   |_|  |_____/_/ \_\ |_____/ \___/ \_/\_/ |_| |_|_|\___/ \__,_|\__,_|\___|_|   
                                                                                                                                 
    """                                                                                                                                 
    print banner
    print "Written by Michael Lim"
    print "v0.1"
    print ""


class FSISAC_STIX_Downloader:
    def __init__(self):
        """ Create STIX_FILES directory if not exists """
        if not os.path.exists(STIX_DOWNLOADED_PATH):
            os.mkdir(STIX_DOWNLOADED_PATH)

    """ Download and process the STIX files from FSISAC """
    def process_fsisac_stix_for_today(self):
        today_str = datetime.datetime.today().strftime('%Y-%m-%d')
        print "[*] Downloading stix for today (%s)..." % (today_str)

        # Create a TAXII Client
        client = tc.HttpClient()
        client.set_auth_type(tc.HttpClient.AUTH_CERT_BASIC) # Username/password plus client cert auth
        client.set_use_https(True) # Use HTTPS

        # Update with your CIR credentials
        client.auth_credentials['username'] = FSISAC_USERNAME
        client.auth_credentials['password'] = FSISAC_PASSWORD
        client.auth_credentials['key_file'] = FSISAC_KEY
        client.auth_credentials['cert_file'] = FSISAC_CERT

        taxii_server = 'analysis.fsisac.com'
        taxii_service = '/taxii-discovery-service/'
        feed = 'system.Default' # TAXII feed to be polled. Update to poll a custom TAXII feed.

        # TAXII poll Exclusive Start Date and Inclusive End Date, as python datetime tuples.
        toyear = datetime.datetime.today().year
        tomonth = datetime.datetime.today().month
        today = datetime.datetime.today().day
        yesterday = datetime.datetime.today() + datetime.timedelta(days=-1)
        yesterday = yesterday.day

        # print "=" * 100
        # print "DEBUGGING"
        # print "=" * 100
        # print toyear, tomonth, yesterday # debug
        # print toyear, tomonth, today # debug
        # print "=" * 100

        if yesterday == 31:
            start = datetime.datetime(toyear, tomonth - 1, yesterday, tzinfo=pytz.UTC)
        else:
            start = datetime.datetime(toyear, tomonth, yesterday, tzinfo=pytz.UTC)

        end = datetime.datetime(toyear, tomonth, today, tzinfo=pytz.UTC)

        # start = datetime.datetime(2019, 4, 5, tzinfo=pytz.UTC)
        # end = datetime.datetime(2019, 4, 5, tzinfo=pytz.UTC)

        # A TAXII poll can return a lot of data. For performance reasons, if the polling period spans multiple days,
        # only poll for one day at a time within the polling period.
        inc_start = start
        inc_end = inc_start + datetime.timedelta(days=1)

        while inc_start <= end:
            params=tm11.PollParameters()
            #Create the TAXII poll request
            poll_request=tm11.PollRequest(tm11.generate_message_id(),
            collection_name=feed,
            poll_parameters=params,
            exclusive_begin_timestamp_label=inc_start,
            inclusive_end_timestamp_label=inc_end)
            poll_xml=poll_request.to_xml()

            # Get the TAXII poll response
            http_resp = client.call_taxii_service2(taxii_server, taxii_service, VID_TAXII_XML_11, poll_xml)
            taxii_message = t.get_message_from_http_response(http_resp, poll_request.message_id)

            # Write each content block from the TAXII poll response to the "path" directory.
            for cb in taxii_message.content_blocks:
                #filename = gen_filename(taxii_message.collection_name, 'FSISAC_STIX111_', cb.timestamp_label.isoformat(), '.xml')
                filename = gen_filename('FSISAC', '_STIX111_', cb.timestamp_label.isoformat(), '.xml')

                with open (STIX_DOWNLOADED_PATH + "/" + filename, 'w') as outfile:
                    outfile.write(cb.content)

                print "Written to %s" % filename

            # Increment to the next day in the specified date range.
            inc_start=inc_start+datetime.timedelta(days=1)
            inc_end=inc_end+datetime.timedelta(days=1)


    """ Write hash value (SHA256) to hash.txt """
    def record_file_hash(self, sha256_hash):
        f = open("hash.txt", "a+")
        f.write(sha256_hash.lower() + "\n")
        f.close()


    """ Check if stix file is already processed before (Based on SHA256) """
    # def check_if_stix_processed(self, stix_filename):
    #     with open(stix_filename, "rb") as f:
    #         bytes = f.read() # read entire file as bytes
    #         sha256_hash = hashlib.sha256(bytes).hexdigest()

    #         if not sha256_hash in self.PROCESSED_HASH:
    #             self.record_file_hash(sha256_hash)
    #             return False
    #         else:
    #             return True


    """ Process all the download STIX files in the directory """
    def process_stix_directory(self):
        # Create 'done' directory if not exists
        if not os.path.exists(STIX_DOWNLOADED_PATH + "/done"):
            os.mkdir(STIX_DOWNLOADED_PATH + "/done")

        stix_files = glob(STIX_DOWNLOADED_PATH + "/*.xml")

        processed_files_count = 0

        for one_file in stix_files:
            filename_only = os.path.basename(one_file)

            # Process stix files
            print ("[+] Process %s..." % (filename_only))
            # FSISAC_JSON_OUTPUT_PATH
            stixParser = FSISAC_STIX_Parser()
            r = stixParser.parse_stix_file(one_file)

            # Write to JSON output directory
            f = open(FSISAC_JSON_OUTPUT_PATH + "/json_" + filename_only.replace(".", "_") + "_" + str(random.randint(1000000000000000, 9999999999999999)) + ".json", "w+")
            f.write(r)
            f.close()

            print ""            

            # Move file to the done directory
            print ("[-] Moved file %s..." % (filename_only))
            os.rename(one_file, STIX_DOWNLOADED_PATH + "/done/" + filename_only)

            # time.sleep(1)

            processed_files_count += 1

        print ""
        print "Processed %s file(s)!" % processed_files_count


if __name__ == "__main__":
    print_banner()

    d = FSISAC_STIX_Downloader()
    d.process_fsisac_stix_for_today()
    d.process_stix_directory()

    print "[Done!]"
