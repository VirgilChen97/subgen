import logging
from url_processor import processors
from urllib.parse import urlparse, parse_qs
from subgen.utils import download_and_cache, decode_base64

SSR_CIPHERS = ['aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb', 'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr', 'rc4-md5',
               'chacha20-ietf', 'xchacha20']


def parse_sub_url(url):
    parsed_url = urlparse(url)
    query = parse_qs(parsed_url.query)

    processor = processors.get(parsed_url.scheme)
    node = processor.process(url, parsed_url, query)

    if node is not None:
        logging.info(f'Successfully parsed {parsed_url.scheme} node {node["name"]}')
    return node


def download_sub_and_parse(url, cache):
    logging.info(f'Processing subscription: {url}')
    raw_sub = download_and_cache(url, cache)
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
