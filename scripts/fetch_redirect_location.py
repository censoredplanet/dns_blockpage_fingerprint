#!/usr/bin/env python3
# coding=utf-8
# Censored Planet 2022
import config
import pandas as pd
import util
import re


def findLoc(l):
    location = None
    start = l.find('Location: ')
    if start != -1:
        start += len('Location: ')
        end = l.find("\'",start)
        location = l[start:end]
    return location


redirect_loc = config.output_loc + '2022-01-02_https_302.csv'
red_df = pd.read_csv(redirect_loc)
red_df['location'] = red_df.content.apply(lambda x: findLoc(x))
red_df = red_df.drop(columns=['content', 'domains', 'standard_deviation'])
print(red_df)
