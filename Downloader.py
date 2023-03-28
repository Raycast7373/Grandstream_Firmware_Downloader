import os
from os import path
import re
from urllib.parse import urlparse
import zipfile
import requests
from bs4 import BeautifulSoup

Grandstream_Devices = ["DP75x", "GDS3702", "GDS3705", "GDS371x", "GRP261x", "GXP2130", "GXP2135", "GXP2140", "GXP2160", "GXP2170", "GXV3370", "WP810_WP822_WP825", "WP820"]
EnableVirusScan = False
RemoveZIPs = False #Currently broken lol

if EnableVirusScan == True: #Only shows you the output from previous scans on Virustotal
    import virustotal_python
    import hashlib
    from pprint import pprint
    API_KEY = "API_KEY_HERE"

def get_available_versions(grandstream_product_name):
    fw_url_pattern = 'https://firmware.grandstream.com/Release_{}_(.*).zip$'
    url_base = 'https://www.grandstream.com'
    strange_url_pattern = 'https://www.grandstream.com/support/firmware/{}-official-firmware'
    url_path = '/support/firmware/'
    url = url_base + url_path
    req = requests.get(url)
    soup = BeautifulSoup(req.content, 'html.parser')
    href = re.compile(fw_url_pattern.format(grandstream_product_name))
    dl_links = soup.find_all('a', href=href)
    if not dl_links:
        url = strange_url_pattern.replace("{}", grandstream_product_name.lower())
        req = requests.get(url)
        soup = BeautifulSoup(req.content, 'html.parser')
        dl_links = soup.find_all('a', href=href)
        print("What a stupid url lol")
    available_versions = []
    available_version_URLS = []
    for link in dl_links:
        match = re.search(href, link.get('href'))
        fw_version = match.group(1)
        fw_link = link.get('href')
        available_version_URLS.append(fw_link)
        available_versions.append(fw_version)
    return available_versions, available_version_URLS

def dl_fw(version):
    filename = os.path.basename(urlparse(version).path)
    response = requests.get(version, allow_redirects=True, stream=True)
    response.raise_for_status()
    open(filename, 'wb').write(response.content)

if RemoveZIPs == True:
    damnzipfiles = os.listdir()
    for item in damnzipfiles:
        if item.endswith(".zip"):
            os.remove(item)

if EnableVirusScan == True:
    with virustotal_python.Virustotal(API_KEY) as vtotal:
        for item in Grandstream_Devices:
            print(item)
            versions, urls = get_available_versions(item)
            print(versions[0])
            print(urls[0])
            print(" ")
            filename = os.path.basename(urlparse(urls[0]).path)
            extract_dir = filename.replace(".zip", "")
            if path.exists(extract_dir) == False:
                if path.exists(filename):
                    os.remove(filename)
                dl_fw(urls[0])
                with open(filename,"rb") as f:
                    bytes = f.read() # read entire file as bytes
                    readable_hash = hashlib.sha256(bytes).hexdigest();
                resp = vtotal.request(f"files/{readable_hash}")
                pprint(resp.data)
                z = zipfile.ZipFile(filename)
                if dir in z.namelist():
                    with zipfile.ZipFile(filename, 'r') as zip_ref:
                        zip_ref.extractall()
                else:
                    with zipfile.ZipFile(filename, 'r') as zip_ref:
                        zip_ref.extractall(extract_dir)    
                #os.remove(filename)
                print("Downloaded Latest Version")
            else:
                print("Latest version already downloaded")
            print(" ")
else:
    for item in Grandstream_Devices:
        print(item)
        versions, urls = get_available_versions(item)
        print(versions[0])
        print(urls[0])
        print(" ")
        filename = os.path.basename(urlparse(urls[0]).path)
        extract_dir = filename.replace(".zip", "")
        if path.exists(extract_dir) == False:
            if path.exists(filename):
                os.remove(filename)
            dl_fw(urls[0])
            z = zipfile.ZipFile(filename)
            if dir in z.namelist():
                with zipfile.ZipFile(filename, 'r') as zip_ref:
                    zip_ref.extractall()
            else:
                with zipfile.ZipFile(filename, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)    
            #os.remove(filename)
            print("Downloaded Latest Version")
        else:
            print("Latest version already downloaded")
        print(" ")
        
if RemoveZIPs == True:
    damnzipfiles = os.listdir()
    for item in damnzipfiles:
        if item.endswith(".zip"):
            os.remove(item)
