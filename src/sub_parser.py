import base64
import logging
from urllib.parse import urlparse, parse_qs, unquote
from utils import download_and_cache

SSR_CIPHERS = ['aes-128-cfb','aes-192-cfb','aes-256-cfb','aes-128-ctr','aes-192-ctr','aes-256-ctr','rc4-md5','chacha20-ietf','xchacha20']

def decode_base64(encoded_str):
    try:
        decoded_bytes = base64.b64decode(encoded_str + '==')
        return decoded_bytes.decode('utf-8')
    except Exception as e:
        raise e

def decode_url_base64(encoded_str):
    try:
        decoded_bytes = base64.urlsafe_b64decode(encoded_str + '==')
        return decoded_bytes.decode('utf-8')
    except Exception as e:
        raise e

def parse_sub_url(url):
    parsed_url = urlparse(url)
    query = parse_qs(parsed_url.query)
    node = {}

    if parsed_url.scheme == 'trojan':
        node = {
            'name': unquote(parsed_url.fragment),
            'type': 'trojan',
            'server': parsed_url.hostname,
            'port': parsed_url.port,
            'password': parsed_url.username,
            'udp': True
        }
        if 'sni' in query:
            node['sni'] = query['sni'][0]
        if 'allowInsecure' in query: 
            node['skip-cert-verify'] = query['allowInsecure'][0] == '1'

    elif parsed_url.scheme == 'ss':
        combination = decode_base64(parsed_url.username).split(':')
        node = {
            'name': unquote(parsed_url.fragment),
            'type': 'ss',
            'server': parsed_url.hostname,
            'port': parsed_url.port,
            'password': combination[1],
            'cipher': combination[0],
            'udp': True
        }

        if 'plugin' in query and query['plugin'][0].startswith('simple-obfs'):
            plugin_config_list = query['plugin'][0].split(';')[1:]
            plugin_config = {k: v for item in plugin_config_list for k, v in [item.split('=')]}
            node['plugin'] = 'obfs'
            node['plugin-opts'] = {}
            node['plugin-opts']['mode'] = plugin_config['obfs']
            node['plugin-opts']['host'] = plugin_config['obfs-host']

    elif parsed_url.scheme == 'ssr':
        real_content = decode_url_base64(url[6:])
        parsed_url = urlparse('ssr://' + real_content)
        query = parse_qs(parsed_url.query)
        combination = parsed_url.netloc.split(':')
        node = {
            'name': decode_url_base64(query['remarks'][0]),
            'type': 'ssr',
            'server': combination[0],
            'port': int(combination[1]),
            'cipher': combination[3],
            'password': decode_url_base64(combination[5]),
            'obfs': combination[4],
            'protocol': combination[2],
            'udp': True
        }
        if 'obfsparam' in query:
            node['obfs-param'] = decode_url_base64(query['obfsparam'][0])
        if 'protoparam' in query:
            node['protocol-param'] = decode_url_base64(query['protoparam'][0])

        try:
            check_ssr_node(node)
        except ValueError as e:
            logging.info(f'{parsed_url.scheme} 节点 {node["name"]} 解析失败, {str(e)}')
            return None

    logging.info(f'{parsed_url.scheme} 节点 {node["name"]} 解析成功')
    return node

def check_ssr_node(node):
    if node['cipher'] not in SSR_CIPHERS:
        raise ValueError(f"SSR 不支持 cipher: {node['cipher']}")

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




