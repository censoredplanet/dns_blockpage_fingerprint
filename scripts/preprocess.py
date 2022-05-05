#!/usr/bin/env python3
# coding=utf-8
# Censored Planet 2022

import re
import pandas as pd
from typing import Dict, Tuple, Optional
from collections import OrderedDict
import structlog
import config


def load_signatures(filepath: str) -> Dict[str, re.Pattern]:
    """Load signatures for blockpage matching.

    Args:
    - filepath: relative path to json file containing signatures

    Returns:
    - Dictionary mapping fingerprints to signature patterns
    """

    data = pd.read_json(filepath, lines=True)
    signatures = OrderedDict()
    for _, row in data.iterrows():
        fingerprint = row['fingerprint']
        pattern = row['pattern']
        signatures[fingerprint] = re.compile(pattern, re.DOTALL)
    return signatures


"""Load TP and FP fingerprints"""
log = structlog.getLogger()
false_positives = load_signatures(config.config_info["false_positive_loc"])
log.info(
    f"Loaded {len(false_positives)} lines of FP fingerprints from {config.config_info['false_positive_loc']}"
)
blockpages = load_signatures(config.config_info["blockpage_loc"])
log.info(
    f"Loaded {len(blockpages)} lines of TP fingerprints from {config.config_info['blockpage_loc']}"
)


def match_page(page: str) -> Tuple[Optional[bool], Optional[str]]:
    """Check if the input page matches a known blockpage or false positive.

    Args:
    - page: a string containing the HTTP body of the potential blockpage

    Returns:
     - (match_outcome, match_fingerprint)
        match_outcome is
            True if page matches a blockpage signature.
            False if page matches a false positive signature.
            None otherwise.
        match_fingerprint is a signature for a blockpage/fp like 'a_prod_cisco'
    """
    for fingerprint, pattern in false_positives.items():
        if pattern.search(page):
            return (False, fingerprint)

    for fingerprint, pattern in blockpages.items():
        if pattern.search(page):
            return (True, fingerprint)

    return (None, None)


def preprocessBlockpageDataframe(blockpage_scan: pd.DataFrame,
                                 dates: str) -> pd.DataFrame:
    """Add fingerprints matching to blockpages.json

    Args:
        blockpage_scan (pd.DataFrame): Fetched Dataframe from BQ
        blockpages (Dict[str, re.Pattern]): TP fingerprints
        false_positives (Dict[str, re.Pattern]): FP fingerprints

    Returns:
        pd.DataFrame: Annotated dataframe
    """
    blockpage_scan['received_page'] = blockpage_scan.received_headers.astype(
        str) + blockpage_scan.received_body.astype(str)
    blockpage_scan['matched_blockpage'], blockpage_scan['fingerprint'] = zip(
        *blockpage_scan.received_page.map(match_page))
    blockpage_scan['https_page_length'] = blockpage_scan.received_page.apply(
        lambda x: len(str(x)))

    if config.config_info['save_intermittent'] == 'True':
        if config.config_info['https_type'] == 'True':
            output_type = 'https'
        else:
            output_type = 'http'
        blockpage_scan.to_csv(
            f'{config.assets_loc}annotated_blockpages_{dates}_{output_type}.csv',
            encoding='utf-8',
            index=False)
    return blockpage_scan
