import requests
from requests.auth import HTTPBasicAuth
from oauthlib.oauth2 import LegacyApplicationClient
from requests_oauthlib import OAuth2Session
import json, pprint

pp = pprint.PrettyPrinter(indent=4).pprint

#sender_ids = requests.get("http://bbc1.interop.tv/x-nmos/connection/v1.0/single/senders/").json()
#print "sender IDs " + str(sender_ids)
#sender_id = sender_ids[0]
#transport_file = requests.get("http://bbc1.interop.tv/x-nmos/connection/v1.0/single/senders/" + sender_id + 'transportfile').text
#print transport_file

#data2 = json.loads(r'''
#{"sender_id":"2e9ca25f-392f-3137-baa0-7fa55dfe67b5","master_enable":true,"activation":{"mode":"activate_immediate"},"transport_file":{"data":"v=0\no=- 1531918517 1531918517 IN IP4 192.168.204.37\ns=IP Studio Stream\nt=0 0\nm=video 5000 RTP/AVP 103\nc=IN IP4 239.20.33.32/32\na=source-filter: incl IN IP4 239.20.33.32 192.168.204.37\na=ts-refclk:ptp=IEEE1588-2008:ec-46-70-ff-fe-00-60-00\na=rtpmap:103 raw/90000\na=fmtp:103 sampling=YCbCr-4:2:2; width=1920; height=1080; depth=10; interlace; SSN=ST2110-20:2017; colorimetry=BT709; PM=2110GPM; TCS=SDR; exactframerate=25\na=mediaclk:direct=0 rate=90000\na=framerate:25.00\n","type":"application/sdp"}}
#''')

#rec_ids = requests.get("http://bbc1.interop.tv/x-nmos/connection/v1.0/single/receivers/").json()
#print "Rec IDs " + str(rec_ids)
#rec_id = rec_ids[0]



def fetch_token():
    client_id = "bbc_client"
    client_secret = "bbc_client"
    username = "bbc_user"
    password = "bbc_user"

    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    data = {'scope' : 'control', 'grant_type' : 'password', 'username' : username, 'password' : password}
    req = requests.post("http://192.168.200.5:9988/token", auth=HTTPBasicAuth(client_id, client_secret), headers = headers, data = data)
    return req.json()

token = fetch_token()
#print token
access_token = token['access_token']
print "Access Token: " + access_token + "\n"

req = requests.get("http://localhost/x-nmos/connection/", headers = {"Authorization":"Bearer " + access_token})
print req.json()
if req.status_code == 200:
    print "SUCCESS \n"
else:
    print "ACCESS DENIED \n"


def find_sender_id():
    r = requests.get("http://bbc1.interop.tv/x-nmos/node/v1.1/flows").json()
    for dic in r:
	if dic["format"] == "urn:x-nmos:format:video":
	    flow_id = dic["id"]
	    print "Flow ID is: " + flow_id
	    re = requests.get("http://bbc1.interop.tv/x-nmos/node/v1.1/senders/").json()
	    for di in re:
		if di["flow_id"] == flow_id:
		    sender_id = di["id"]
		    print "Sender ID is: " + sender_id
		    return sender_id
		else:
		    pass
	else:
	    pass
    print "Could not find Sender ID!"
    return None

def find_receiver_id():
    r = requests.get("http://bbc2.interop.tv/x-nmos/node/v1.1/receivers/").json()
    for dic in r:
	if dic["format"] == "urn:x-nmos:format:video":
	    rec_id = dic["id"]
	    print "Rec. ID is: " + rec_id + "\n"
	    return rec_id
	else:
	    pass
    print "Could not find Receiver ID!"
    return None

def find_transport_file():
    url = "http://bbc1.interop.tv/x-nmos/connection/v1.0/single/senders/" + sender_id + "/transportfile"
    #print "Transport File URL is: " + url + "\n"
    tf = requests.get(url).text
    #print tf
    return tf

sender_id = find_sender_id()
receiver_id = find_receiver_id()
transport_file = find_transport_file()

data2 = {"sender_id": sender_id,"master_enable":True,"activation":{"mode":"activate_immediate"},"transport_file": {"data": transport_file, "type":"application/sdp"}}
#print data2

patch_url = "http://bbc2.interop.tv/x-nmos/connection/v1.0/single/receivers/" + receiver_id + "/staged"
print patch_url

req2 = requests.patch(patch_url, headers = {"Authorization":"Bearer " + access_token}, json = data2)
#print req2.json()
if req2.status_code == 404:
    print "Cannot Find IS-05 Receivers"
elif req2.status_code != 200:
    print "Failed with Status Code: " + str(req2.status_code)
elif req2.status_code == 200:
    print "Successful PATCH"

def pretty_print_POST(req):
    """
    At this point it is completely built and ready
    to be fired; it is "prepared".

    However pay attention at the formatting used in 
    this function because it is programmed to be pretty 
    printed and may differ from the actual request.
    """
    print('{}\n{}\n{}\n\n{}'.format(
        '-----------START-----------',
        req.method + ' ' + req.url,
        '\n'.join('{}: {}'.format(k, v) for k, v in req.headers.items()),
        req.body,
    ))

req2 = requests.Request('PATCH', patch_url, headers = {"Authorization":"Bearer " + access_token}, json = data2)
prepared = req2.prepare()
pretty_print_POST(prepared)








