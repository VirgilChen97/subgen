import logging
from subgen.parser.url_processor import processors
from urllib.parse import urlparse, parse_qs
from ..utils import download_and_cache, decode_base64

SSR_CIPHERS = ['aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb', 'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr', 'rc4-md5',
               'chacha20-ietf', 'xchacha20']


def parse_sub_url(url):
    parsed_url = urlparse(url)
    query = parse_qs(parsed_url.query)

    processor = processors.get(parsed_url.scheme)
    node = processor.process(url, parsed_url, query)

    if node is not None:
        logging.info(f'{parsed_url.scheme} 节点 {node["name"]} 解析成功')
    return node


def download_sub_and_parse(url, cache):
    logging.info(f'开始处理订阅: {url}')
    raw_sub = download_and_cache(url, cache)
    decoded = decode_base64(raw_sub)
    lines = decoded.split('\n')
    nodes = []
    for line in lines:
        if line != '':
            node = parse_sub_url(line)
            if node is not None:
                nodes.append(node)

    logging.info(f'处理完成，共处理节点 {len(nodes)} 个')
    return nodes
