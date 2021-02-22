import requests
import json
from urllib.parse import urlparse
from alexa_siterank import *

def get_domain_age_in_days(domain):
    show = "https://input.payapi.io/v1/api/fraud/domain/age/" + domain
    data = requests.get(show).json()
    return data['result'] if 'result' in data else None

def get_alexa_rank(url):
    return getRank(url)['rank']['global']

def parse_domain_from_url(url):
    t = urlparse(url).netloc
    return '.'.join(t.split('.')[-2:])
    
def fqdn_len(url):
    t = urlparse(url).netloc
    return len(t)

def count_subdomains(url):
    t = urlparse(url).netloc
    return t.count('.')-1
    
def count_terms(url):
    t = urlparse(url).netloc
    return t.count('-')+1
    
def get_redirects_dest_from_url(url, n):
    try:
        data = requests.head(url, allow_redirects=False)
        status_code = data.status_code
    except:
        status_code = 0
    
    if (status_code == 301 or status_code == 302 or status_code == 303):
        if (n >= 1):
            return {"url": "", "n+1": n+1}
        
        new_url = data.next.url
        
        return get_redirects_dest_from_url(new_url, n+1)
      
    else:
        return {"url": url, "num": n}
      
def term_count(data, term):
    return data.text.count(term)

def analyze_url(url):
    n_subdomains = count_subdomains(url)
    len_fqdn = fqdn_len(url)
    n_terms = count_terms(url)
    
    if (n_subdomains < 0):
      print("Invalid url: \"" + url + "\"")
      return
      
    # If domain is new it could indicate that the bad guy has bought it recently...
    try:
        age_in_days_feature = get_domain_age_in_days(parse_domain_from_url(url));
    except:
        age_in_days_feature = ""
        
    # Usually not much need for multiple redirects
    res1 = get_redirects_dest_from_url(url, 0)
    landing_url = res1["url"]
    n_redirects = res1["num"]
    
    # Alexa rank is a good indicator that a site is not a phishing site
    try:
        alexa_rank = get_alexa_rank(url)
    except:
        alexa_rank = False
    
    mld = urlparse(url).netloc.split('.')[-2]
    mld_count = 0
    landing_mld = urlparse(landing_url).netloc.split('.')[-2]
    landing_mld_count = 0
    
    try:
        data = requests.get(landing_url)
        
        if (data.ok):
            # A phisher is less likely to have a domain name with the same name as the service
            mld_count = term_count(data, mld)
            # A lot of sites have a shortened version that doesn't match the real name and redirects to the actual site
            landing_mld_count = term_count(data, landing_mld)
    except Exception as e:
        print("Couldn't connect to site: \"" + landing_url + "\"")
        # print(e)
    
    return {
      "url": url,
      "landing_url": landing_url,
      "n_subdomains": n_subdomains,
      "len_fqdn": len_fqdn,
      "age_in_days": age_in_days_feature,
      "landing url": landing_url,
      "n_redirects": n_redirects,
      "n_terms": n_terms,
      "alexa rank": alexa_rank,
      "mld_count": mld_count,
      "landing_mld_count": landing_mld_count
    }

# Note some of these urls are live phishing sites (as of 2021-02-05) use with caution! More can be found at https://www.phishtank.com/
example_urls = [
                  "google.com",
                  "https://google.co/",
                  "https://www.slideshare.net/weaveworks/client-side-monitoring-with-prometheus",
                  "https://www.slideshare.net/weaveworks/client-side-monitoring-with-prometheus",
                  "https://intezasanpaolo.com/",
                  "http://sec-login-device.com/",
                  "http://college-eisk.ru/cli/",
                  "https://dotpay-platnosc3.eu/dotpay/"
               ]
               
data_set = []

for url in example_urls:
    try:
        data = analyze_url(url)
        if (data != None):
            data_set.append(data)
    except Exception as e:
        print("Caught exception:")
        print(e)

for data in data_set:
    print(str(data))