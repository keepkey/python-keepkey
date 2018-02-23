#!/usr/bin/env python3

"""
Downloads all assets attached to tagged releases in a given repo, and stores them in a shelf.
"""

import os
import sys
import hashlib
import hmac
import base64
import requests
import shelve

from collections import OrderedDict

REPO_ORG =repo_org = "keepkey"
REPO_NAME = repo_name="keepkey-firmware"
SHELF_NAME = ".release_binaries.shelf"

hmac_hash_func = hashlib.sha256
bin_hash_func = hashlib.sha256

def bin_digest(*args, **kwargs):
    return bin_hash_func(*args, **kwargs).hexdigest()

def shelve_assets(repo_org=REPO_ORG, repo_name=REPO_NAME):
    with requests.Session() as s:
        #get all tagged releases for this repo
        r = s.get("https://api.github.com/repos/{}/{}/releases".format(repo_org, repo_name))
        if not r.ok: r.raise_for_status()
        releases_by_version = sorted(r.json(), key=lambda x: x.get('tag_name'))
        
        release_binaries = OrderedDict({})
        for this_release in releases_by_version:
            #pull the tag name for each release and download attached asset binaries
            tag_name = this_release.get('tag_name')
            release_assets = release_binaries[tag_name] = {}
            
            for this_asset in this_release.get('assets'):            
                #fetch the asset binary
                asset_name = this_asset.get('name')
                print("Downloading {} asset {}".format(tag_name, asset_name))
                asset_url = this_asset.get('browser_download_url')
                asset_req = s.get(asset_url)
                if not asset_req.ok: asset_req.raise_for_status()
                
                #encode asset into marshallable format
                raw_asset = asset_req.content
                b64_asset = base64.b64encode(raw_asset).decode('utf8')
                hex_digest = bin_digest(raw_asset)
                print("Storing as {}".format(hex_digest))
                release_assets[asset_name] = {'b64_asset':b64_asset,
                                              'hex_digest':hex_digest,
                                             }
    
    #shelve the release binaries
    with shelve.open(SHELF_NAME) as open_shelf:
        open_shelf.update(release_binaries)


def fetch_asset(target_hex_digest):
    if not os.path.exists(SHELF_NAME): raise ValueError("{} not found ".format(SHELF_NAME))
    with shelve.open(SHELF_NAME) as open_shelf:
        for this_release_name,this_release in open_shelf.items():
            for this_asset_name, this_asset in this_release.items():
                if this_asset.get('hex_digest') == target_hex_digest:
                    return this_asset


def hmac_asset(nonce, target_hex_digest):
    return hmac.new(nonce.encode('utf8'), fetch_asset(target_hex_digest.encode('utf8')), hmac_hash_func)


if __name__ == "__main__":
    shelve_assets()
    BIN_HASH = '6b93bedad6effa79f6f8f170f78eebfbbc7618f8e0151f262e1e314bb5776a4c'
    import pprint
    pprint.pprint(fetch_asset(BIN_HASH))
    pprint.pprint(hmac_asset("secret_nonce", BIN_HASH).hexdigest())





