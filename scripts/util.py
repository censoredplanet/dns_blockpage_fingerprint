#!/usr/bin/env python3
# coding=utf-8
# Censored Planet 2022
import math
from collections import Counter
import operator
import tldextract
import ast


def matchListItem(content, l):
    matched = [fp for fp in l if fp in content]
    if len(matched) == 0:
        return -1
    else:
        return matched[0]


def matchList(content, l):
    return any([e in str(content) for e in l])


def getFirstRow(df, ip, status_list):
    for _, row in df[(df.ip == ip)
                     & (df.received_status.isin(status_list))].iterrows():
        return row['received_page']


def normalized_stdev(page_length):
    avg = sum(page_length) / len(page_length)
    dist = sum((x - avg)**2 for x in page_length)
    normalized_stdev = math.sqrt(dist) / avg
    if normalized_stdev > 1:
        return 1
    return normalized_stdev


def calIPSimilarityHTTPS(df, ip, status_list):
    page_length = df[(df.ip == ip) &
                     (df.received_status.isin(status_list))].https_page_length
    if len(page_length) == 0:
        return None
    std_dev = normalized_stdev(page_length)
    avg_length = sum(page_length) / len(page_length)
    domain_length = df[(df.ip == ip) & (
        df.received_status.isin(status_list))].domain.nunique()
    similarity = 1 - std_dev / avg_length
    # significance = similarity * domain_length
    return {
        'ip': ip,
        'domain_count': domain_length,
        'avg_length': avg_length,
        'standard_deviation': std_dev,
        'similarity': similarity,
    }


def calIPSimilarityHTTP(df, ip, s):
    page_length = df[(df.ip == ip) & (df.http_status == s)].http_page_length
    if len(page_length) == 0:
        return None
    std_dev = normalized_stdev(page_length)
    avg_length = sum(page_length) / len(page_length)
    domain_length = df[(df.ip == ip) & (df.http_status == s)].domain.nunique()
    similarity = 1 - std_dev / avg_length
    # significance = similarity * domain_length
    return {
        'ip': ip,
        'domain_count': domain_length,
        'avg_length': avg_length,
        'standard_deviation': std_dev,
        'similarity': similarity,
    }


def getOrderedCount(l):
    counted = sorted(Counter(l).items(), key=operator.itemgetter(1))
    counted.reverse()
    return counted


def tld(domain):
    return tldextract.extract(domain).domain


def sameTLD(domain, matching):
    """
    matching: list or str
    """
    if not domain or not matching:
        return None
    if type(matching) is list:
        return any([sameTLD(domain, domain2) for domain2 in matching])
    return tld(domain) == tld(matching)


def reverseList2Dict(l):
    string = ', '.join(l)
    string = '{' + string + '}'
    try:
        res = ast.literal_eval(string)
    except:
        res = string
    return res


def redirectMatch(location, domain):
    if not location or not domain:
        return False
    return tld(domain) in location


def getBQredLoc(l):
    location = None
    for item in l:
        if "Location" in item:
            location = item.split(': ')[1]
    return location


def ipListPercentage(df, l):
    lines = df[df.received_ip.isin(l)].shape[0]
    total = df.shape[0]
    print(f"{lines}/{total} = {lines*100/total}%")
    return lines / total


def calCertSimilarity(df, domain, s):
    page_length = df[(df.cert_domain == domain) & (
        df.https_status == s)].https.apply(lambda x: len(str(x))).tolist()
    if len(page_length) == 0:
        return None
    std_dev = normalized_stdev(page_length)
    avg_length = sum(page_length) / len(page_length)
    domain_length = df[(df.cert_domain == domain)
                       & (df.https_status == s)].keyword.nunique()
    similarity = 1 - std_dev / avg_length
    # significance = similarity * domain_length
    return {
        'cert': domain,
        'domain_count': domain_length,
        'avg_length': avg_length,
        'standard_deviation': std_dev,
        'similarity': similarity,
    }


def calOrgSimilarity(segment, org, s):
    page_length = segment[(segment.cert_org == org)
                          & (segment.https_status == s)].https.apply(
                              lambda x: len(str(x))).tolist()
    if len(page_length) == 0:
        return None
    std_dev = normalized_stdev(page_length)
    avg_length = sum(page_length) / len(page_length)
    domain_length = segment[(segment.cert_org == org)
                            & (segment.https_status == s)].keyword.nunique()
    similarity = 1 - std_dev / avg_length
    # significance = similarity * domain_length
    return {
        'org': org,
        'domain_count': domain_length,
        'avg_length': avg_length,
        'standard_deviation': std_dev,
        'similarity': similarity,
    }


def printFirstRow(df, t):
    #print(f"{df.shape[0]} rows in total")
    for _, row in df.iterrows():
        print(f"domain: {row['keyword']}, {row[t]}"
              )  #, row['https']['headers']['Location']
        break


def checkRedirect(domain, body):
    try:
        return tld(domain) in body['headers']['Location'][0]
    except:
        return False
