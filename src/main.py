import yaml
import logging
import sys
import os
import argparse
from config import Config
from config import Proxy

# 创建一个ArgumentParser对象
parser = argparse.ArgumentParser(description='Clash 配置生成工具')

# 添加命令行参数
parser.add_argument('-c', '--config', help='配置文件路径')
parser.add_argument('-o', '--output', help='输出文件的路径')
parser.add_argument('--loglevel', help='日志级别', default='INFO')

# 解析命令行参数
args = parser.parse_args()

# 配置日志记录器
log_level = getattr(logging, args.loglevel, None)
logging.basicConfig(
    level=log_level if log_level is None else logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

if args.config is None:
    logging.error("未提供配置文件路径")
    exit(1)

if args.output is None:
    logging.error("未提供输出文件路径")

if not os.path.exists(args.config):
    logging.error("配置文件路径非法")
    exit(1)

# 读取配置文件
generation_config = Config(args.config)

# 提取节点信息
all_proxies = [Proxy(subscription.tag, proxy['name'], proxy)
               for subscription in generation_config.subscriptions
               for proxy in subscription.data
               ]

# 读取基础配置
base_config = None
with open(generation_config.base, 'r') as file:
    base_config = yaml.safe_load(file)

# 节点添加基础配置节点
all_proxies = [Proxy("", proxy['name'], proxy) for proxy in base_config['proxies']] + all_proxies

# 写入 proxies
base_config['proxies'] = [proxy.data for proxy in all_proxies]

# 生成 proxy groups
base_config['proxy-groups'] = []
for proxy_group in generation_config.proxy_groups:
    base_config['proxy-groups'].append(proxy_group.generate(all_proxies))

# 生成 rules
base_config['rules'] = []
for ruleset in generation_config.rulesets:
    ruleset_rules = ruleset.generate()
    for ruleset_rule in ruleset_rules:
        base_config['rules'].append(ruleset_rule.to_string())

# 将新生成的配置写入文件
with open(args.output, 'w') as file:
    yaml.dump(base_config, file, allow_unicode=True, sort_keys=False, Dumper=yaml.SafeDumper)
