import logging
from url_processor import processors
from urllib.parse import urlparse, parse_qs
from utils import decode_base64


def parse_sub_url(url):
    parsed_url = urlparse(url)
    query = parse_qs(parsed_url.query)

    processor = processors.get(parsed_url.scheme)
    node = processor.process(url, parsed_url, query)

    if node is not None:
        logging.info(f'Successfully parsed {parsed_url.scheme} node {node["name"]}')
    return node


def parse(raw_sub, url):
    logging.info(f'Processing subscription: {url}')
    decoded = decode_base64(raw_sub)
    lines = decoded.split('\n')
    nodes = []
    for line in lines:
        if line != '':
            node = parse_sub_url(line)
            if node is not None:
                nodes.append(node)

    logging.info(f'Subscription processing complete，total nodes: {len(nodes)}')
    return nodes
