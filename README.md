# FSISAC STIX Downloader

__FSISAC STIX Downloader__ is a script to pull FSISAC (STIX Version 1.1.1) from FSISAC Taxii Server. The main issue with FSISAC STIX feeds is it has IOCs written in all-text description and not in seperate XML nodes. The script will download and convert the STIX files to JSON (RFC 4627) files into local directory. Title in the STIX is parsed and preserved in the JSON too.

Before using the script, please configure the settings in fsisac.conf. The configuration items are self-explanatory.

## Usage
* Install python requirements
```
pip install -r requirements.txt
```

* Run the Downloader, it will pull the STIX files based on today's date.
```
python FSISAC_STIX_Downloader.py
```
## ArcSight Integration
You can use ArcSight connector to parse the JSON and send to ArcSight ESM.

## Contact
ch4meleon@protonmail.com

