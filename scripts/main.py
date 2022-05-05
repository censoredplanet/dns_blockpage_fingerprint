#!/usr/bin/env python
# coding=utf-8
# Censored Planet 2022

from tracemalloc import start

from numpy import block
import config
import structlog
import bigquery
import util
import preprocess
import pandas as pd


def getStatusDict(df: pd.DataFrame) -> dict:
    """Generate mapping of HTTP status code and received_status field from BQ table

    Args:
        df (pd.DataFrame): Dataframe grepped from GB table 

    Returns:
        dict: example: '302': {'302 ', '302 Found', '302 Moved Temporarily', '302 Moved temporarily', '302 Redirect'}
    """
    number2status = dict()
    for status in df.received_status.unique():
        if util.matchList(status, ["Get", "net", "EOF", 'read']):
            continue
        number = status.split(' ')[0]
        if number not in number2status:
            number2status[number] = set()
        number2status[number].add(status)
    return dict(sorted(number2status.items()))


def getDates(df: pd.DataFrame) -> str:
    """Generate timespan according to df.date

    Args:
        df (pd.DataFrame): Raw or annotated blockpage table

    Returns:
        str: timespan
    """
    start_date = min(df.date.unique())
    end_date = max(df.date.unique())

    if start_date == end_date:
        dates = start_date
    else:
        dates = start_date + "-" + end_date
    return dates


if __name__ == "__main__":
    log = structlog.getLogger()
    start_time = config.config_info['start_time']
    end_time = config.config_info['end_time']
    https_type = config.config_info['https_type']
    similarity_thres = float(config.config_info['similarity_threshold'])
    min_tld_thres = int(config.config_info['tld_threshold'])

    if https_type == "True":
        https_outcome = "https"
    else:
        https_outcome = "http"

    # Abort match-case since yapf fails
    if config.config_info["read_file_logic"] == "0":

        # Scenario one: Read table from BQ
        log.info(
            f"Loading table from BQ {start_time} - {end_time}, https={https_type}"
        )
        df = bigquery.getBQBlockpageDataframe(True)
        dates = getDates(df)
        log.debug(df.head())
        # Add blockpage fingerprints
        blockpage_scan = preprocess.preprocessBlockpageDataframe(df, dates)
        log.debug(
            f"dates={dates}, lines={df.shape[0]}, matched_lines={blockpage_scan[blockpage_scan['matched_blockpage'] == True].shape[0]}"
        )
    elif config.config_info["read_file_logic"] == "1":
        raw_table_loc = config.config_info["raw_table_loc"]
        log.info(f"Loading table from local file={raw_table_loc}")
        df = pd.read_csv(f'{config.assets_loc}{raw_table_loc}')
        dates = getDates(df)
        # Add blockpage fingerprints
        blockpage_scan = preprocess.preprocessBlockpageDataframe(df, dates)
        log.debug(
            f"dates={dates}, lines={df.shape[0]}, matched_lines={blockpage_scan[blockpage_scan['matched_blockpage'] == True].shape[0]}"
        )
    elif config.config_info["read_file_logic"] == "2":
        annotated_loc = config.config_info["annotated_loc"]
        log.info(f"Loading annotated table from {annotated_loc}")
        blockpage_scan = pd.read_csv(f'{config.assets_loc}{annotated_loc}')
        dates = getDates(blockpage_scan)
        log.debug(
            f"dates={dates}, lines={blockpage_scan.shape[0]}, matched_lines={blockpage_scan[blockpage_scan['matched_blockpage'] == True].shape[0]}"
        )
    else:
        raise Exception(
            f"Error read file logic={config.config_info['read_file_logic']}")

    number2status = getStatusDict(blockpage_scan)
    log.debug(
        f"ip_cnt={blockpage_scan.ip.nunique()}, status_dict_keys={number2status.keys()}"
    )

    redirect_status = []
    for status in number2status.keys():
        if int(status) // 100 == 3:
            redirect_status.append(status)
            continue
        all_ips = util.getOrderedCount(
            blockpage_scan[blockpage_scan.received_status.isin(
                number2status[status])].ip)

        log.debug(f"Starting checking {status} on {dates}...")
        segment = blockpage_scan[blockpage_scan.received_status.isin(
            number2status[status])]

        ip_candidates = []
        for ip, _ in all_ips:
            if segment[segment.ip == ip].domain.nunique() > 1:
                status_count = segment[(segment.ip == ip)].shape[0]
                if status_count > 1:
                    ip_candidates.append(ip)

        ip_info = []
        for ip in ip_candidates:
            if status in config.special_ips and util.matchList(
                    ip, config.special_ips[status]):
                continue
            domains = segment[(segment.ip == ip)
                              & (segment.received_status.isin(
                                  number2status[status]))].domain.unique()
            unique_tlds = set([util.tld(domain) for domain in domains])
            matched = segment[(segment.ip == ip) & (
                segment.received_status.isin(number2status[status])
            )].matched_blockpage.unique()
            if https_type == "True":
                info = util.calIPSimilarityHTTPS(segment, ip,
                                                 number2status[status])
            else:
                info = util.calIPSimilarityHTTP(segment, ip,
                                                number2status[status])
            if not info:
                continue
            if True in matched:
                # If this page is already a matched blockpage - skip
                log.debug(
                    f"TP - {ip} -- {info['standard_deviation']}, domains={info['domain_count']}, tlds={len(unique_tlds)}"
                )
            elif info[
                    'standard_deviation'] < similarity_thres and False not in matched:
                if False in segment[(segment.ip == ip) & (
                        segment.received_status.isin(number2status[status])
                )].matched_blockpage.unique():
                    # if match FP fingerprint - skip
                    log.debug(
                        f"FP - {ip} -- {info['standard_deviation']}, domains={info['domain_count']}, tlds={len(unique_tlds)}"
                    )
                    continue
                if len(ip) < 2 or len(unique_tlds) < min_tld_thres:
                    continue
            ip_info.append(info)
            log.debug(
                f"{ip} -- {info['standard_deviation']}, domains={info['domain_count']}, tlds={len(unique_tlds)}, {matched}"
            )
            log.debug(
                f"Finishing checking {status} on {dates}, {len(ip_info)} found."
            )
        if len(ip_info) == 0:
            continue

        ip_info = pd.DataFrame(ip_info)
        ip_info['content'] = ip_info.ip.apply(
            lambda x: util.getFirstRow(segment, x, number2status[status]))
        ip_info['domains'] = ip_info.ip.apply(
            lambda x: segment[segment.ip == x].domain.unique())
        target_loc = f'{config.output_loc}{dates}_{https_outcome}_{status}.csv'
        ip_info.to_csv(target_loc, encoding='utf-8', index=False)
        log.debug(f"Saved to {target_loc}\n")

    redirect_received_status = []
    for status in redirect_status:
        redirect_received_status += number2status[status]

    segment = blockpage_scan[blockpage_scan.received_status.isin(
        redirect_received_status)]
    segment['location'] = segment.received_headers.apply(
        lambda x: util.getBQredLoc(x))
    # Check if TLD matches
    segment['redirect_match'] = segment.apply(
        lambda x: util.redirectMatch(x.location, x.domain), axis=1)

    redirect_cnt = segment.shape[0]
    segment = segment[segment['redirect_match'] == False]
    all_ips = util.getOrderedCount(segment.ip)
    log.info(
        f"{redirect_cnt} lines of 300+ redirects, {segment.shape[0]} lines of misdirects, {len(all_ips)} IPs hosting redirect pages."
    )

    for status in redirect_status:
        ip_info = []
        for ip, _ in all_ips:
            if segment[segment.ip == ip].domain.nunique() > 1:
                status_count = segment[(segment.ip == ip)].shape[0]
                if status_count < 2:
                    continue

                domains = segment[(segment.ip == ip)
                                  & (segment.received_status.isin(
                                      number2status[status]))].domain.unique()
                unique_tlds = set([util.tld(domain) for domain in domains])
                if len(ip) < 2 or len(unique_tlds) < min_tld_thres:
                    continue
                matched = segment[(segment.ip == ip) & (
                    segment.received_status.isin(number2status[status])
                )].matched_blockpage.unique()
                if https_type == "True":
                    info = util.calIPSimilarityHTTPS(segment, ip,
                                                     number2status[status])
                else:
                    info = util.calIPSimilarityHTTP(segment, ip,
                                                    number2status[status])

                if not info:
                    continue
                if True in matched:
                    log.debug(
                        f"TP - {ip} -- {info['standard_deviation']}, domains={info['domain_count']}, tlds={len(unique_tlds)}"
                    )
                elif (info['standard_deviation'] <
                      similarity_thres) and False in matched:
                    log.debug(
                        f"FP - {ip} -- {info['standard_deviation']}, domains={info['domain_count']}, tlds={len(unique_tlds)}"
                    )
                    continue
            ip_info.append(info)
            print(
                f"{ip} -- {info['standard_deviation']}, domains={info['domain_count']}, tlds={len(unique_tlds)}, {matched}"
            )
        print(f"Finishing checking {status} on {dates}, {len(ip_info)} found")
        if len(ip_info) != 0:
            ip_info = pd.DataFrame(ip_info)

            ip_info['content'] = ip_info.ip.apply(
                lambda x: util.getFirstRow(segment, x, number2status[status]))
            ip_info['domains'] = ip_info.ip.apply(
                lambda x: segment[segment.ip == x].domain.unique())
            target_loc = f'{config.output_loc}{dates}_{https_outcome}_{status}.csv'
            ip_info.to_csv(target_loc, encoding='utf-8', index=False)
            log.debug(f"Saved to {target_loc}\n")
