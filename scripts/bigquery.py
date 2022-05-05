#!/usr/bin/env python3
# coding=utf-8
# Censored Planet 2022

import pandas as pd
import time
import structlog
import config

log = structlog.getLogger()


class Timer:

    def __enter__(self):
        self.t = time.perf_counter()
        return self

    def __exit__(self, type, value, traceback):
        self.t = time.perf_counter() - self.t

    def __float__(self):
        return float(self.t)

    def __str__(self):
        return str(float(self))


def getBQBlockpageDataframe():
    """
    Get blockpage Dataframe from Google BigQuery
    
    Example:
    - start_time: "2020-01-01"
    - end_time: "2020-12-31"
    - https: "True"
    
    Return:
    - df: fetched Dataframe
    """
    with Timer() as t:
        project_id = config.config_info['bq_org']

        start_time = config.config_info['start_time']
        end_time = config.config_info['end_time']
        https_type = config.config_info['https_type']

        sql = '''
            SELECT
                domain,
                ip,
                date,
                https,
                received_status,
                received_body,
                received_headers,
            FROM `{}`
            WHERE
                date BETWEEN {}
                AND {} AND
                https = {}
        '''.format(config.config_info['bq_table'], "\'" + start_time + "\'",
                   "\'" + end_time + "\'", https_type)

        df = pd.io.gbq.read_gbq(sql, project_id=project_id)

    log.debug(
        f"Grepped blockpage dataframe for {start_time} - {end_time} in {t} sec"
    )
    if config.config_info['save_intermittent'] == 'True':
        if https_type == 'True':
            output_type = 'https'
        else:
            output_type = 'http'
        df.to_csv(
            f'{config.assets_loc}blockpages_{output_type}_{start_time}-{end_time}.csv',
            encoding='utf-8',
            index=False)
    return df
