#RVCH - Scan for clients miscategorised on SSID Block policy

# Requires requests and meraki packages
# https://github.com/meraki/dashboard-api-python/blob/master/meraki.py
#       pip3 install requires
#       pip3 install meraki

# Client OS requires GDPR feature enabled on Dashboard
#       or a European hosted organisation
# Contact Meraki Support to have feature enabled

from meraki import meraki
import json
import requests
import sys
#TODO import tkinter for gui

base_url = 'https://api.meraki.com/api/v0'

def getclientinfo(netid, clientid, suppressprint=True):
    """
    Args:
        netid: Network to scan for clients
        clientid: id of Client to get information including OS
        suppressprint:
    Returns:
        Dict of client information
    """

    geturl = '{0}/networks/{1}/clients/{2}'.format(str(base_url), str(netid), str(clientid))
    headers = {
        'x-cisco-meraki-api-key': format(str(apikey)),
        'Content-Type': 'application/json'
    }
    try:
        dashboard = requests.get(geturl, headers=headers)
        #print(dashboard.text)
        parsed_json = json.loads(dashboard.text)
        return parsed_json
    except:
        print('Error: Could not read Client Info for', clientid)

def checkclientpolicy(netid, clientid):
    """
    Func:
        Checks a client for a Custom policy per SSID. If set, check the OS.
        If the OS should not be blocked, unblock the policy.
    Args:
        netid: Network that the client is in
        clientid: id of Client to check/update policy of
    Returns:
        null
    """

    try:
        clientInfo = getclientinfo(netid, clientid)
        print('\t\t\tClient name: ', clientInfo['description'], 'MAC:', clientInfo['mac'], '\n\t\t\t\tManufacturer:', clientInfo['manufacturer'], 'OS:', clientInfo['os'])
        policy = meraki.getclientpolicy(apikey, netid, clientInfo['mac'], timestamp=1200, suppressprint=True)
        print('\t\t\t\tPolicy: ', policy['type'])
        #TODO: Test based on SSID
        #if clientInfo['ssid'] == ssid-to-test:
        #   do-the-thing
        # "Different policies by SSID" - want more granularity in the return, in case an SSID is whitelisted, or a different SSID is blocked
        if policy['type'] in ('Different policies by SSID'):
            if 'OS X' in clientInfo['os']:
                print('!!! Blocked client detected !!!')
                meraki.updateclientpolicy(apikey, netid, clientInfo['mac'], 'normal', policyid=None, suppressprint=True)
            elif 'Windows' in clientInfo['os']:
                if 'Phone' not in clientInfo['os']:
                    print('!!! Blocked client detected !!!')
                    meraki.updateclientpolicy(apikey, netid, clientInfo['mac'], 'normal', policyid=None, suppressprint=True)
    except:
        print('Unable to check client policy')
        #TODO: understand why some clients can't be read

def getnetworks():
    orgList = meraki.myorgaccess(apikey, True)
    for orgs in orgList:
        try:
            orgid = orgs['id']
            print('Organisation: ', orgs['name'])
            return meraki.getnetworklist(apikey, orgid, templateid=None, suppressprint=True)
        except:
            print('Could not retrieve network list in Organisation ', orgid)
            exit()


##############################################################################

# !!!Don't hardcode API key!!! - pass as parameter, keep secure
if len(sys.argv) == 1:
    print('Usage: update-policy.py <api-key> (optional <network ID>)')
    exit()
else:
    apikey = sys.argv[1]

#Takes a hard-coded network ID - needs to be of type N_ or L_
if len(sys.argv) == 2:
    print('No network passed, assuming all networks in all organisations')
    #TODO: get list of networks in org, pass them recursively below
    #getnetworks()
    print('not currently supported, quitting...')
    exit()
elif len(sys.argv) >= 3:
    netid = sys.argv[2]
    if netid[0] not in ('N', 'L'):
        print('Network ID should begin with N_ or L_')
        print('Quitting...')
        exit()

devList = meraki.getnetworkdevices(apikey, netid, suppressprint=True)
for devs in devList:
    serial = devs['serial']
    print('\t\tSerial: ', serial)
    clientList = meraki.getclients(apikey, serial, timestamp=1200, suppressprint=True)
    for client in clientList:
        clientid = client['id']
        checkclientpolicy(netid, clientid)
