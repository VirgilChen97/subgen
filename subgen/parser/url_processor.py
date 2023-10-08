import logging
from abc import abstractmethod
from urllib.parse import unquote, urlparse, parse_qs

from ..utils import decode_base64, decode_url_base64


class UrlProcessor:
    @abstractmethod
    def check_data(self, node):
        pass

    @abstractmethod
    def parse_node(self, url, parsed_url, query):
        pass

    def process(self, url, parsed_url, query):
        node = self.parse_node(url, parsed_url, query)

        try:
            self.check_data(node)
            return node
        except ValueError as e:
            logging.info(f'{node["name"]} 节点检查失败, 原因: {str(e)}')
            return None


# Trojan URL 处理
# 暂不支持 ws 和 gRPC
# https://dreamacro.github.io/clash/configuration/outbound.html#trojan
class TrojanUrlProcessor(UrlProcessor):
    MANDATORY_KEY = ['name', 'server', 'port', 'password']

    def check_data(self, node):
        for key in self.MANDATORY_KEY:
            if node.get(key, "") == "":
                raise ValueError(f'trojan 节点缺失 {key}')

    def parse_node(self, url, parsed_url, query):
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

        return node


# SS URL 处理
# 不支持 ws
# https://dreamacro.github.io/clash/configuration/outbound.html#shadowsocks
class ShadowsocksUrlProcessor(UrlProcessor):
    SUPPORTED_CIPHERS = ['aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305',
                         'xchacha20-ietf-poly1305', 'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb', 'rc4-md5',
                         'chacha20-ietf', 'xchacha20', 'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr']

    MANDATORY_KEY = ['name', 'server', 'port', 'password', 'cipher']

    def check_data(self, node):
        for key in self.MANDATORY_KEY:
            if node.get(key, "") == "":
                raise ValueError(f'ss 节点缺失 {key}')

        if node['cipher'] not in self.SUPPORTED_CIPHERS:
            raise ValueError(f'ss 节点不支持 {node["cipher"]}')

        return True

    def parse_node(self, url, parsed_url, query):
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

        return node


# SSR URL 处理
class ShadowsocksRUrlProcessor(UrlProcessor):
    SUPPORTED_CIPHERS = ['aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb', 'rc4-md5', 'chacha20-ietf', 'xchacha20']
    SUPPORTED_OBFS = ['plain', 'http_simple', 'http_post', 'random_head', 'tls1.2_ticket_auth',
                      'tls1.2_ticket_fastauth']
    SUPPORTED_PROTOCOLS = ['origin', 'auth_sha1_v4', 'auth_aes128_md5', 'auth_aes128_sha1', 'auth_chain_a',
                           'auth_chain_b']
    MANDATORY_KEY = ['name', 'server', 'port', 'password', 'cipher', 'obfs', 'protocol']

    def check_data(self, node):
        for key in self.MANDATORY_KEY:
            if node.get(key, "") == "":
                raise ValueError(f'ssr 节点缺失 {key}')

        if node['cipher'] not in self.SUPPORTED_CIPHERS:
            raise ValueError(f'ssr 节点不支持 cipher: {node["cipher"]}')
        if node['obfs'] not in self.SUPPORTED_OBFS:
            raise ValueError(f'ssr 节点不支持 obfs: {node["obfs"]}')
        if node['protocol'] not in self.SUPPORTED_PROTOCOLS:
            raise ValueError(f'ssr 节点不支持 protocol: {node["protocol"]}')

    def parse_node(self, url, parsed_url, query):
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

        return node


processors = {
    'trojan': TrojanUrlProcessor(),
    'ss': ShadowsocksUrlProcessor(),
    'ssr': ShadowsocksRUrlProcessor()
}
