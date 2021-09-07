#!/usr/bin/env python3
"""
Download content of a URL and save it to a file.
"""
import requests
url = "https://en.wikipedia.org/wiki/List_of_Law_%26_Order:_Special_Victims_Unit_episodes_(seasons_1%E2%80%9319)#Season_1_(1999%E2%80%932000)"

content = requests.get(url).content

with open('source.html', 'wb') as f:
    f.write(content)