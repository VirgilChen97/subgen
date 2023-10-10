import base64
import hashlib
import ipaddress
import logging
import os
import requests
import yaml
from datetime import datetime

CACHE_DIR = "cache"


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


def is_valid_ipv6(address):
    try:
        ipaddress.IPv6Network(address, strict=False)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_valid_ipv4(address):
    try:
        ipaddress.IPv4Network(address, strict=False)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def calculate_url_hash(url):
    """计算URL的哈希值作为缓存文件名"""
    hash_object = hashlib.md5(url.encode())
    return hash_object.hexdigest()


def read_yaml_string(yaml_string):
    try:
        yaml_data = yaml.safe_load(yaml_string)
        return yaml_data
    except yaml.YAMLError as e:
        logging.error(f"YAML parse error: {e}")
        raise e


class ExternalResource:
    def __init__(self, resource_type, url, cache_time, proxy=None):
        self.cache = cache_time if cache_time is not None else 86400
        self.proxy = proxy
        self.resource_type = resource_type
        self.url = url

    def load(self):
        if self.resource_type == 'http':
            try:
                current_time = datetime.now()
                url_hash = calculate_url_hash(self.url)
                cache_file = os.path.join(CACHE_DIR, f'{url_hash}.cache')

                # 检查缓存文件是否存在并且未过期
                if os.path.exists(cache_file):
                    cached_time = (current_time - datetime.fromtimestamp(os.path.getmtime(cache_file))).total_seconds()
                    if cached_time < self.cache:
                        logging.info(f"Using cached resource: {self.url}, cached time: {int(cached_time)}s, cache time: {self.cache}s")
                        with open(cache_file, 'rb') as file:
                            cached_data = file.read()
                        return cached_data.decode('utf-8')

                logging.info(f"Downloading resource: {self.url}")
                proxies = None
                if self.proxy is not None:
                    logging.info(f"Using proxy: {self.proxy}")
                    proxies = {
                        'http': self.proxy,
                        'https': self.proxy
                    }

                response = requests.get(self.url, proxies=proxies)
                response.raise_for_status()  # 检查是否下载成功

                # 获取响应的二进制数据
                downloaded_data = response.content

                # 将新下载的数据写入缓存文件
                with open(cache_file, 'wb') as file:
                    file.write(downloaded_data)

                return downloaded_data.decode('utf-8')

            except requests.exceptions.RequestException as e:
                logging.error(f"HTTP reqeust error: {e}")
                raise e

        elif self.resource_type == 'file':
            with open(self.url, 'rb') as file:
                data = file.read()
            return data.decode('utf-8')

        else:
            raise ValueError(f"不支持的 type: {self.resource_type}")
