import logging, json, requests, hashlib, yaml, os, re, ipaddress
from datetime import datetime, timedelta
from utils import download_and_cache, read_yaml_string

class Config:
    def __init__(self, config_file_path):
        try:
            logging.info("读取配置文件: " + config_file_path)
            with open(config_file_path, 'r') as config_file:
                config_dict = json.load(config_file)
                self.parse_config(config_dict)
                
        except Exception as e:
            logging.info("读取配置文件失败: " + config_file_path, e)
            raise e
            

    def parse_config(self, config_dict):
        self.base = config_dict['base']
        self.subscriptions = [Subscription(
            subscription.get('tag'), 
            subscription.get('url'),
            subscription.get('cache')
        ) for subscription in config_dict['subscriptions']]
        self.proxy_groups = [ProxyGroup(
            proxy_group.get('type'),
            proxy_group.get('name'),
            proxy_group.get('test_url'),
            proxy_group.get('interval'),
            proxy_group.get('tolerance'),
            proxy_group.get('filters'),
            proxy_group.get('includes')
        ) for proxy_group in config_dict['proxy_groups']]
        self.rulesets = [Ruleset(
            ruleset.get('type'),
            ruleset.get('url'),
            ruleset.get('params'),
            ruleset.get('target')
        ) for ruleset in config_dict['rulesets']]

class Proxy: 
    def __init__(self, tag: str, name: str, data: dict):
        self.tag = tag
        self.name = name
        self.data = data

class Filter:
    def __init__(self, type, regex=r'.*', negative_regex=r'^(?!.*\S).*$'):
        self.type = type
        if regex is not None:
            self.regex = regex
        else:
            self.regex = r'.*'
        if negative_regex is not None:
            self.negative_regex = negative_regex
        else:
            self.negative_regex = r'^(?!.*\S).*$'

    def filter(self, proxies: list[Proxy]):
        if self.type == 'tag':
            return [proxy for proxy in proxies if self.check_regex_condition(proxy.tag)]
        elif self.type == 'name':
            return [proxy for proxy in proxies if self.check_regex_condition(proxy.name)]
        else:
            raise ValueError("不支持的 Filter 类型: " + self.type)
    
    def check_regex_condition(self, input_string):
        # 检查是否存在满足正则表达式的子串
        if re.search(self.regex, input_string):
            # 检查是否存在满足负正则表达式的子串
            if not re.search(self.negative_regex, input_string):
                return True
        return False
            

class ProxyGroup:
    def __init__(self, type: str, name: str, test_url: str, 
    interval: int, tolerance: int, filters: list = [], includes: list = []):
        self.type = type
        self.name = name
        self.test_url = test_url
        self.interval = interval
        self.tolerance = tolerance

        if filters is None:
            filters = []
        self.filters = [Filter(
            filter_item.get('type'),
            filter_item.get('regex'),
            filter_item.get('negative_regex')
        ) for filter_item in filters]

        if includes is None:
            includes = []
        self.inludes = includes

    def generate(self, proxies: list[Proxy]):
        # 筛选代理列表
        if self.filters == None or len(self.filters) == 0:
            proxies = []
        else:
            for filter_item in self.filters:
                proxies = filter_item.filter(proxies)
        
        if self.type == 'url-test':
            return {
                'name': self.name,
                'type': 'url-test',
                'url': self.test_url,
                'interval': self.interval,
                'tolerance': self.tolerance,
                'proxies': [proxy.name for proxy in proxies] + self.inludes
            }
        elif self.type == 'select':
            return {
                'name': self.name,
                'type': 'select',
                'proxies': [proxy.name for proxy in proxies] + self.inludes
            }
        else:
            raise ValueError('不支持的 Proxy Group Type: ' + self.type)

class Rule:
    def __init__(self, rule_type: str, param: str, target:str):
        self.rule_type = rule_type
        self.param = param
        self.target = target

    def to_string(self):
        if self.param is None:
            return self.rule_type + ','  + self.target
        return self.rule_type + ',' + self.param + ',' + self.target

class Ruleset:
    def __init__(self, rules_type: str, url: str, params: list, target: str):
        self.type = rules_type
        self.url = url
        self.params = params
        self.target = target
        if url is not None:
            self.data = download_and_parse_yaml(self.url)['payload']

    def generate(self):
        if self.type == 'classic':
            return self.generate_clash_classic()
        elif self.type == 'match':
            return [Rule("MATCH", None, self.target)]
        elif self.type == 'ipcidr':
            return self.generate_clash_ipcidr()
        elif self.type == 'domain':
            return self.generate_clash_domain()
        else:
            return self.generate_clash()

    def generate_clash_classic(self):
        rules = []
        for line in self.data:
            line_data = line.split(',')
            rules.append(Rule(line_data[0], line_data[1], self.target))
        return rules

    def generate_clash_domain(self):
        rules = []
        for line in self.data:
            if line.startswith('+.'):
                rules.append(Rule('DOMAIN-SUFFIX', line[2:], self.target))
            else:
                rules.append(Rule('DOMAIN', line, self.target))
        return rules

    def generate_clash_ipcidr(self):
        rules = []
        for line in self.data:
            if is_valid_ipv4(line):
                rules.append(Rule('IP-CIDR', line, self.target))
            elif is_valid_ipv6(line):
                rules.append(Rule('IP-CIDR6', line, self.target))
            else:
                raise ValueError(line + " 不是合法的 IP 地址")
        return rules

    def generate_clash(self):
        rules = []
        if self.url is None:
            for param in self.params:
                rules.append(Rule(self.type, param, self.target))
        else:
            for line in self.data:
                rules.append(Rule(self.type, line, self.target))
        return rules


class Subscription:
    def __init__(self, tag: str, url: str, cache: int = 86400):
        self.tag = tag
        self.url = url
        self.cache = cache
        self.data = read_yaml_string(download_and_cache(self.url, self.cache).decode('utf-8'))

            
