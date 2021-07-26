#!/usr/bin/env python
# coding: utf-8

# In[1]:


import sys
import pandas as pd
import numpy as np
import sklearn
import requests
import re
import time


# In[2]:


#format URL, adding appropriate headers
def URL_format(url):
    http_flag = 0
    www_flag = 0
    new_url = ""
    
    if "http" not in url[:4]:
        http_flag = 1
    if "www" not in url[:11]:
        www_flag = 1

    if http_flag == 1:
        try:
            r = requests.get('https://'+ url, timeout=10)
            new_url = "https://"
        except:
            new_url = "http://"
            
        if www_flag == 1:
            new_url = new_url + "www."
            
        new_url = new_url+url
    else:
        if www_flag == 1:
            if url[:5] == "https":
                new_url = url[:8] + "www." + url[8:]
            elif url[:4] == "http":
                new_url = url[:7] + "www." + url[7:]
        else:
            new_url = url
    time.sleep(1/4)
    return new_url

#Length of URL
def URL_len(url):
    return len(url)

#Length of Hostname
def hostname_len(url):
    #assumes we start with ://www....
    matches = re.findall("://www.([\w\-\.]+)", str(url))
    result = 0
    if (len(matches) >= 1):
        result = len(matches[0])
    return result

#Length of path
def path_len(url):
    match_len = len(re.findall("://www.[\w\-\.]+([\/\w+]*)", str(url)))
    if (match_len > 0):
        return len(re.findall("://www.[\w\-\.]+([\/\w+]*)", str(url))[0])
    return match_len

#Length of first directory
def first_dir_len(url):
    match_len = len(re.findall("://www.[\w\-\.]+(\/\w+)", str(url)))
    if (match_len > 0):
        return len(re.findall("://www.[\w\-\.]+(\/\w+)", str(url))[0])
    return match_len
    
#Length of top level domain
def top_level_len(url):
    domains = re.findall("://www.([\w\-\.]+)", str(url))
    if len(domains) != 0:
        tld = domains[0].split('.')
        return len(tld[-1])
    return 0

#Count of '-'
def count_dash(url):
    dashes = 0
    for char in url:
        if char == '-':
            dashes += 1     
    return dashes

#Count of '@'
def count_at(url):
    at = 0
    for char in url:
        if char == '@':
            at += 1     
    return at

#Count of '?'
def count_q(url):
    q = 0
    for char in url:
        if char == '?':
            q += 1     
    return q

#Count of '%'
def count_percent(url):
    percent = 0
    for char in url:
        if char == '%':
            percent += 1     
    return percent

#Count of '.'
def count_dot(url):
    dot = 0
    for char in url:
        if char == '.':
            dot += 1     
    return dot

#Count of '='
def count_equal(url):
    eq = 0
    for char in url:
        if char == '=':
            eq += 1     
    return eq

#Count of ';'
def count_colon(url):
    colon = 0
    for char in url:
        if char == ';':
            colon += 1     
    return colon

#Count of 'www'
def count_www(url):
    www = 0
    www = len(re.findall("www", str(url)))
    return www

#Count of numbers
def count_numbers(url):
    numbers = sum(c.isdigit() for c in url)
    return numbers

#Count of letters
def count_letters(url):
    letters = sum(c.isalpha() for c in url)
    return letters

#Count of directories
def dir_count(url):
    dirs = 0
    for char in url:
        if char == '/':
            dirs = dirs + 1
    #assumes that it starts with ://www....
    return dirs - 2

#Count of single letter directories
def single_letter_dir(url):
    sldir = 0
    sldir = len(re.findall("\/[\w]\/", str(url)))
    return sldir
                
#Count of queries
def query_count(url):
    count = 0
    count = len(re.findall("\?\w+(&?\w+)*", str(url)))
    return count

#Ratio of uppercase to lowercase letters
def ratio_upper_lower(url):
    upperSum = 0
    lowerSum = 0
    for char in url:
        if char.isupper():
            upperSum = upperSum + 1
        if char.islower():
            lowerSum = lowerSum + 1
    # if url has 0 of one, this will return 0
    if lowerSum == 0:
        return upperSum
    return upperSum / lowerSum

#IP vs not
def is_ip(url):
    if len(re.findall("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", str(url))) > 0:
        return 1
    else:
        return 0
    
# Shortened or not
def is_shortened(url):
    shortened = { "bit.ly", "tinyurl", "goo.gl", "ow.ly", "t.co", 
                 "tiny.cc", "bit.do", "shorte.st", "cutt.ly", "clkim"}
    
    if any(shrt in url for shrt in shortened):
        return 1
    else:
        return 0

#HTTP vs. HTTPS
#Returns 1 if HTTPS, 0 if HTTP
def is_https(url):
    if url[:5] == 'https':
        return 1
    elif url[:4] == 'http':
        return 0


# In[3]:


#Read csv data using pandas
majestic_million=pd.read_csv('data/majestic_million.csv')
phishtank=pd.read_csv('data/phistank_verified_online_data.csv')

#Only take the first 10,000 values of the majestic million values
majestic_million=majestic_million.head(10000)

#Rows are store in res[] after being processed
res=[]

malicious=0
benign=1


# In[ ]:



for index,row in majestic_million.iterrows():
    #print(row.IDN_Domain)
    url = URL_format(row.IDN_Domain)
    print(index)
    print(url)

    url_res = URL_len(url)
    hostname_res = hostname_len(url)
    path_res = path_len(url)
    first_dir_res = first_dir_len(url)
    top_level_res = top_level_len(url)
    dash_res = count_dash(url)
    at_res = count_at(url)
    q_res = count_q(url)
    percent_res = count_percent(url)
    dot_res = count_dot(url)
    equal_res = count_equal(url)
    colon_res = count_colon(url)
    www_res = count_www(url)
    numbers_res = count_numbers(url)
    letters_res = count_letters(url)
    dir_res = dir_count(url)
    single_letter_res = single_letter_dir(url) 
    query_res = query_count(url)
    ratio_upper_lower_res = ratio_upper_lower(url)
    ip_res = is_ip(url)
    shortened_res = is_shortened(url)
    http_res = is_https(url)
    
    res.append([url,benign,url_res,hostname_res ,path_res,first_dir_res,top_level_res,dash_res,at_res,q_res,percent_res,dot_res,equal_res,colon_res,www_res,numbers_res,letters_res,dir_res,single_letter_res,query_res,ratio_upper_lower_res,ip_res,shortened_res,http_res])
  
result_column_names = ['url','malicious','url_res','hostname_res','path_res','first_dir_res','top_level_res','dash_res','at_res','q_res','percent_res','dot_res','equal_res','colon_res','www_res','numbers_res','letters_res','dir_res','single_letter_res','query_res','ratio_upper_lower_res','ip_res','shortened_res','http_res']

result_majestic = pd.DataFrame(res,columns=result_column_names)
result_majestic.to_csv('data/majestic_out.csv', sep=',',index=False)


# In[4]:


res=[]
for index,row in phishtank.iterrows():
    #print("original: " + row.url)
    url = row.url
    print(index)
    print(url)
    
    url_res = URL_len(url)
    hostname_res = hostname_len(url)
    path_res = path_len(url)
    first_dir_res = first_dir_len(url)
    top_level_res = top_level_len(url)
    dash_res = count_dash(url)
    at_res = count_at(url)
    q_res = count_q(url)
    percent_res = count_percent(url)
    dot_res = count_dot(url)
    equal_res = count_equal(url)
    colon_res = count_colon(url)
    www_res = count_www(url)
    numbers_res = count_numbers(url)
    letters_res = count_letters(url)
    dir_res = dir_count(url)
    single_letter_res = single_letter_dir(url) 
    query_res = query_count(url)
    ratio_upper_lower_res = ratio_upper_lower(url)
    ip_res = is_ip(url)
    shortened_res = is_shortened(url)
    http_res = is_https(url)
    
    res.append([url,malicious,url_res,hostname_res ,path_res,first_dir_res,top_level_res,dash_res,at_res,q_res,percent_res,dot_res,equal_res,colon_res,www_res,numbers_res,letters_res,dir_res,single_letter_res,query_res,ratio_upper_lower_res,ip_res,shortened_res,http_res])
result_column_names = ['url','malicious','url_res','hostname_res','path_res','first_dir_res','top_level_res','dash_res','at_res','q_res','percent_res','dot_res','equal_res','colon_res','www_res','numbers_res','letters_res','dir_res','single_letter_res','query_res','ratio_upper_lower_res','ip_res','shortened_res','http_res']

result = pd.DataFrame(res,columns=result_column_names)
result.to_csv('data/phistank_out.csv', sep=',',index=False)


# In[5]:


#Extra test data
kaggle=pd.read_csv('data/kaggle_shuff.csv')
kaggle=kaggle.head(10000)

kaggle_rows=[]

malicious=0
benign=1

for index,row in kaggle.iterrows():
    #print(row.url)
    url = row.url
    print(index)
    print(url)
    
    if row.label == 'benign':
        good_or_bad = benign
    else:
        good_or_bad = malicious

    url_res = URL_len(url)
    hostname_res = hostname_len(url)
    path_res = path_len(url)
    first_dir_res = first_dir_len(url)
    top_level_res = top_level_len(url)
    dash_res = count_dash(url)
    at_res = count_at(url)
    q_res = count_q(url)
    percent_res = count_percent(url)
    dot_res = count_dot(url)
    equal_res = count_equal(url)
    colon_res = count_colon(url)
    www_res = count_www(url)
    numbers_res = count_numbers(url)
    letters_res = count_letters(url)
    dir_res = dir_count(url)
    single_letter_res = single_letter_dir(url) 
    query_res = query_count(url)
    ratio_upper_lower_res = ratio_upper_lower(url)
    ip_res = is_ip(url)
    shortened_res = is_shortened(url)
    http_res = is_https(url)
    
    res.append([url,good_or_bad,url_res,hostname_res ,path_res,first_dir_res,top_level_res,dash_res,at_res,q_res,percent_res,dot_res,equal_res,colon_res,www_res,numbers_res,letters_res,dir_res,single_letter_res,query_res,ratio_upper_lower_res,ip_res,shortened_res,http_res])
  
kaggle_column_names = ['url','malicious','url_res','hostname_res','path_res','first_dir_res','top_level_res','dash_res','at_res','q_res','percent_res','dot_res','equal_res','colon_res','www_res','numbers_res','letters_res','dir_res','single_letter_res','query_res','ratio_upper_lower_res','ip_res','shortened_res','http_res']

result_kaggle = pd.DataFrame(res,columns=kaggle_column_names)
result_kaggle.to_csv('data/kaggle_out.csv', sep=',',index=False)

