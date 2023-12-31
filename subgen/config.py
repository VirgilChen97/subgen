import json
import logging
import re

from sub_parser import parse
from utils import read_yaml_string, is_valid_ipv4, is_valid_ipv6, ExternalResource


class Config:
    def __init__(self, config_file_path):
        self.rulesets = None
        self.proxy_groups = None
        self.subscriptions = None
        self.base = None

        try:
            logging.info("Loading config file: " + config_file_path)
            with open(config_file_path, 'r', encoding='utf-8') as config_file:
                config_dict = json.load(config_file)
                self.parse_config(config_dict)

        except Exception as e:
            logging.info("Loading config file failed: " + config_file_path, e)
            raise e

    def parse_config(self, config_dict):
        self.subscriptions = [Subscription(
            subscription.get('tag'),
            subscription.get('url'),
            subscription.get('cache'),
            subscription.get('type'),
            subscription.get('proxy')
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
            ruleset.get('target'),
            ruleset.get('cache'),
            ruleset.get('resource_type'),
            ruleset.get('proxy')
        ) for ruleset in config_dict['rulesets']]
        pass


class Proxy:
    def __init__(self, tag: str, name: str, data: dict):
        self.tag = tag
        self.name = name
        self.data = data


class Filter:
    def __init__(self, filter_type, regex=r'.*', negative_regex=r'^(?!.*\S).*$'):
        self.type = filter_type
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
            raise ValueError("Unsupported filter type: " + self.type)

    def check_regex_condition(self, input_string):
        # 检查是否存在满足正则表达式的子串
        if re.search(self.regex, input_string):
            # 检查是否存在满足负正则表达式的子串
            if not re.search(self.negative_regex, input_string):
                logging.debug(f'{input_string} satisfies regex: {self.regex} -regex:{self.negative_regex}')
                return True

        logging.debug(f'{input_string} not satisfy regex:{self.regex} -regex:{self.negative_regex}')
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
        self.includes = includes

    def generate(self, proxies: list[Proxy]):
        # 筛选代理列表
        logging.info(f"Generation proxy group [{self.name}], type: {self.type}")
        proxy_list = []

        if self.filters is None or len(self.filters) == 0:
            proxy_list = []
        else:
            proxy_list = proxies.copy()
            for filter_item in self.filters:
                proxy_list = filter_item.filter(proxy_list)

        result = {}
        if self.type == 'url-test':
            result = {
                'name': self.name,
                'type': 'url-test',
                'url': self.test_url,
                'interval': self.interval,
                'tolerance': self.tolerance,
                'proxies': [proxy.name for proxy in proxy_list] + self.includes
            }
        elif self.type == 'select':
            result = {
                'name': self.name,
                'type': 'select',
                'proxies': [proxy.name for proxy in proxy_list] + self.includes
            }
        else:
            raise ValueError('Unsupported proxy group type: ' + self.type)

        logging.info(f"Generate proxy group [{self.name}] success, node count: {len(result['proxies'])}")
        return result


class Rule:
    def __init__(self, rule_type: str, param: str, target: str):
        self.rule_type = rule_type
        self.param = param
        self.target = target

    def to_string(self):
        if self.param is None:
            return self.rule_type + ',' + self.target
        return self.rule_type + ',' + self.param + ',' + self.target


class Ruleset(ExternalResource):
    def __init__(self, rules_type: str, url: str, params: list, target: str, cache: int, resource_type: str, proxy: str):
        self.rules_type = rules_type
        self.params = params
        self.target = target
        super().__init__(resource_type, url, cache, proxy)
        if url is not None:
            self.data = read_yaml_string(self.load())['payload']

    def generate(self):
        logging.info(f"Generate rules from {self.url} , TARGET: {self.target}")
        if self.rules_type == 'classic':
            return self.generate_clash_classic()
        elif self.rules_type == 'match':
            return [Rule("MATCH", None, self.target)]
        elif self.rules_type == 'ipcidr':
            return self.generate_clash_ipcidr()
        elif self.rules_type == 'domain':
            return self.generate_clash_domain()
        elif self.url is None:
            return self.generate_clash()
        else:
            logging.error(f'Unsupported rule type: {self.rules_type}')
            raise ValueError()

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
                raise ValueError(line + " is not valid ip address")
        return rules

    def generate_clash(self):
        rules = []
        if self.url is None:
            for param in self.params:
                rules.append(Rule(self.rules_type, param, self.target))
        else:
            for line in self.data:
                rules.append(Rule(self.rules_type, line, self.target))
        return rules


class Subscription(ExternalResource):
    def __init__(self, tag: str, url: str, cache: int, resource_type: str, proxy: str):
        self.tag = tag
        self.url = url
        self.cache = cache
        super().__init__(resource_type, url, cache, proxy)
        self.data = parse(self.load(), self.url)
