import requests
import json

Headers={'Cookie': '<ENTER YOUR SESSION COOKIE HERE>'}

url = 'https://netbox.<DOMAIN>.com/api/ipam/ip-addresses/?format=json'

print(f"Scrapping {url}")
response = requests.request("GET", url, headers=Headers).json()
c=0
f=open('ipdb.csv','w')
f_bulk=open('ipdb-bulk.jsonline','w')
while True:
    if 'next' in response.keys():
        url = response['next']
        for item in response['results']:
            f_bulk.write(json.dumps(item))
            f_bulk.write('\n')
            f.write(",".join([item['dns_name'], item['address']]))
            f.write('\n')
        print(url)
        try:
            response=requests.request("GET", url,headers=Headers).json()
        except:
            break
        c+=1
        if url==None:
            break
    else:
        f_bulk.write(json.dumps(item))
        f_bulk.write('\n')
        f.write(",".join([item['dns_name'], item['address']]))
        f.write('\n')
        break

f.close()
f_bulk.close()

print("Performed %d queries" % (c))