import base64
from urllib.parse import urlparse, parse_qs, unquote
from utils import download_and_cache

def decode_base64(encoded_bytes):
    try:
        decoded_bytes = base64.b64decode(encoded_bytes + b'==')
        return decoded_bytes
    except Exception as e:
        raise e

def parse_sub_url(url):
    parsed_url = urlparse(url)
    query = parse_qs(parsed_url.query)

    if parsed_url.scheme == 'trojan':
        trojan_node = {
            'name': unquote(parsed_url.fragment),
            'type': 'trojan',
            'server': parsed_url.hostname,
            'port': parsed_url.port,
            'password': parsed_url.username,
            'udp': true
        }
        if 'type' in query and query['sni'][0] == 'ws':
            trojan_node['sni'] = query['sni'][0]
            trojan_node['skip-cert-verify'] = query['allowInsecure'][0] == '1'

    elif parsed_url.scheme == 'ss':
        combination = decode_base64(parsed_url.username).split(':')
        ss_node = {
            'name': unquote(parsed_url.fragment),
            'type': 'ss',
            'server': parsed_url.hostname,
            'port': parsed_url.port,
            'password': combination[1],
            'cipher': combination[0]
        }

        if 'plugin' in query and query['plugin'][0].startswith('simple-obfs'):
            plugin_config_list = query['plugin'][0].split(';')[1:]
            plugin_config = {k: v for item in plugin_config_list for k, v in [item.split('=')]}
            ss_node['plugin-opts'] = {}
            ss_node['plugin-opts']['mode'] = plugin_config['obfs']
            ss_node['plugin-opts']['host'] = plugin_config['obfs-host']

    elif parsed_url.scheme == 'ssr':
        real_content = decode_base64(url[6:])
        parsed_url = urlparse('ssr://' + real_content)
        print(real_content)

#    elif parse_url.scheme == 'ssr':

def download_sub_and_parse(url):
    raw_sub = download_and_cache(url)
    decoded = decode_base64(raw_sub)
    line = decoded.split('\n')
    parse_sub_url(line[0])

download_sub_and_parse('https://sub.qiduo.eu.org/link/AJ6rVdmv0RQhJF5c?mu=1')




