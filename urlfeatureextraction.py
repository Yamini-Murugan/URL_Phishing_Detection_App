# Feature Extraction - This File extracts 19 Categorial features from URLs
# to build the final dataset that will be used to train the Deep Learning Models

# Importing required packages 
import re
import whois
from datetime import datetime
from googlesearch import search
import re
from urllib.parse import urlparse
import ipaddress
import csv
import requests

#---Address Bar based feature extraction from url ---#

# Extracts the domain name from the URL
def extractdom(url):
  domain = urlparse(url).netloc
  if re.match(r"^www.",domain):
    domain = domain.replace("www.","") # Returns the domain without www.
  return domain 

# Checks for IP Address in URL 
def checkip(url):
  try:
    ipaddress.ip_address(url)
    ip = 1   #phishing
  except:
    ip = 0   #benign
  return ip

# Checks for '@' symbol in URL
def symbol(url):
  if "@" in url:
    at = 1    #phishing
  else:
    at = 0    
  return at

# Checks for length of URL, longer URL means phishing
def extractlenght(url):
  if len(url) < 54:
    length = 0            
  else:
    length = 1    #phishing       
  return length
     
# Checks the depth of URL by calculating number of sub pages in url based on '/'
def extractdepth(url):
  s = urlparse(url).path.split('/')
  depth = 0   
  for j in range(len(s)):
    if len(s[j]) != 0:
      depth = depth+1 # A higher depth can indicate more complex URLs, often associated with phishing.
  return depth

# Checks for redirection '//' in url by checking the position of // after (http://)
def redirecting(url):
  pos = url.rfind('//')
  if pos > 6:
    if pos > 7:
      return 1   #phishing 
    else:
      return 0
  else:
    return 0

# Checks for “HTTP/HTTPS” Token in URL 
def checkhttpdomain(url):
  domain = urlparse(url).netloc
  if "http" in domain or "https" in domain:
    return 1 #phishing
  else:
    return 0 
     
# ----listing shortening services ---#

services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"
                      
# Checks for Shortening Services used in URL 

# If the URL is using Shortening Services, the value assigned to this feature is 1 (phishing) or else 0 (legitimate).
def tinyURL(url):
    match=re.search(services,url)
    if match:
        return 1  #phishing
    else:
        return 0

# Checks for Prefix or Suffix Separated by (-) 
def prefixsuffixcheck(url):
    if '-' in urlparse(url).netloc:
        return 1 #phishing
    else:
        return 0 

# Loading Alexa Top Domains for determining URL traffic rank

# Reading the Alexa top 1 million website data from a top-1m.csv file,
# parsing it, and storing it in a list (alexa) for further use 
with open('top-1m.csv') as f:
  reader = csv.reader(f)
  alexa = list(reader)
  
#---- Domain Based feature extraction from url -----#

# Check web page rank from top 1 millon list

def traffic_check(url, alexa):
    domain = extractdom(url)
    # Create a dictionary for faster lookup of domain rank
    alexa_dict = {v[1]: i + 1 for i, v in enumerate(alexa)}
    # Check if the domain is in the Alexa dataset
    rank = alexa_dict.get(domain)
    if rank is None:
        # If domain is not found in the Alexa dataset, return 1 (indicating phishing)
        return 1
    # Rank logic: If rank is below 100000, it's a legitimate site (0); else, it's phishing (1)
    if rank < 100000:
        return 0  
    else:
        return 1  # Phishing 

# Check if domain age is less than 6 months 
def dmage(domain_name):
  creation_date = domain_name.creation_date
  expiration_date = domain_name.expiration_date
  if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
    try:
      creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
      expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
    except:
      return 1
  if ((expiration_date is None) or (creation_date is None)):
      return 1
  elif ((type(expiration_date) is list) or (type(creation_date) is list)):
      return 1
  else:
    # Domain Age - The difference between termination time and creation time  
    ageofdomain = abs((expiration_date - creation_date).days)
    if ((ageofdomain/30) < 6):
      age = 1  #phishing
    else:
      age = 0
  return age

# Checks If domain end > 6 months, then feature is 1 (phishing) else 0.
def dmend(domain_name):
  expiration_date = domain_name.expiration_date
  if isinstance(expiration_date,str):
    try:
      expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
    except:
      return 1
  if (expiration_date is None):
      return 1
  elif (type(expiration_date) is list):
      return 1
  else:
    today = datetime.now()
    # Domain End - The difference between termination time and current time  
    end = abs((expiration_date - today).days)
    if ((end/30) < 6):
      end = 0
    else:
      end = 1  #phishing
  return end

#----Content (HTML & JS ) Based Feature extraction ---------------#

# Checks for IFrame Redirection
# if iframe is not found then phishing
def IframeRedirection(response):
  if response == "":
      return 1 #phish
  else:
      if re.findall(r"[<iframe>|<frameBorder>]", response.text):
          return 0  
      else:
          return 1 #phish

# Checks for number of redirects  
def WebsiteForwarding(response):
  if response == "":
    return 1
  else:
    if len(response.history) <= 2:
      return 0
    else:
      return 1  #phishing

# Checks if right click is disabled
def DisableRightClick(response):
  if response == "":
    return 1
  else:
    if re.findall(r"event.button ?== ?2", response.text):
      return 0
    else:
      return 1  #phishing

# Checks the effect of mouse over on status bar 
def StatusBarCust(response): 
  if response == "" :
    return 1
  else:
    if re.findall("<script>.+onmouseover.+</script>", response.text):
      return 1   #phishing
    else:
      return 0

# Checks the number of links pointing to the webpage 
def LinksPointingToPage(response):
  try:
      number_of_links = len(re.findall(r"<a href=", response.text))
      print(number_of_links)
      if number_of_links == 0:
          return 1 #phishing
      elif number_of_links <= 2:
          return -1 #Suspicious
      else:
          return 0
  except:
      return 0

# Checks if Webpage is Indexed by Google
def GoogleIndex(url):
  try:
      site = search(url, num_results=5)
      if site:
          return 0 
      else:
          return 1
  except:
      return 0 

# Function to extract features
def urlfeature_extractor(url):
  # Address Bar based feature extraction 
  cols = []
  cols.append(extractdom(url))
  cols.append(checkip(url))
  cols.append(symbol(url))
  cols.append(extractlenght(url))
  cols.append(extractdepth(url))
  cols.append(redirecting(url))
  cols.append(checkhttpdomain(url))
  cols.append(tinyURL(url))
  cols.append(prefixsuffixcheck(url))

  #Domain based features 
  dns = 0
  try:
    domain_name = whois.whois(urlparse(url).netloc)
  except:
    dns = 1
  cols.append(dns)
  cols.append(traffic_check(url,alexa))
  cols.append(1 if dns == 1 else dmage(domain_name))
  cols.append(1 if dns == 1 else dmend(domain_name))

  # HTML & Javascript based features
  try:
    response = requests.get(url)
  except:
    response = ""

  cols.append(IframeRedirection(response))
  cols.append(StatusBarCust(response))
  cols.append(DisableRightClick(response))
  cols.append(WebsiteForwarding(response))
  cols.append(LinksPointingToPage(response))
  cols.append(GoogleIndex(url))
  return cols
