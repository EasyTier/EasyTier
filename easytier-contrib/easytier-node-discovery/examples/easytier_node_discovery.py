#!/usr/bin/env python3
"""
EasyTier 动态节点发现脚本

这是一个简单的外挂脚本，用于自动发现和更新 EasyTier 节点。
支持 HTTP、TXT DNS 和 SRV DNS 协议。

用法:
    python3 easytier_node_discovery.py --config-url http://config-server.com/nodes
    python3 easytier_node_discovery.py --config-url txt://txt.easytier.cn
    python3 easytier_node_discovery.py --config-url srv://example.com
"""

import argparse
import time
import sys
import logging
from typing import Set, Optional
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("Error: requests library is required. Install with: pip install requests")
    sys.exit(1)

try:
    import dns.resolver
except ImportError:
    print("Warning: dnspython not installed. TXT/SRV discovery will not work.")
    print("Install with: pip install dnspython")
    dns = None

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class NodeDiscoveryManager:
    """节点发现管理器"""
    
    def __init__(
        self,
        config_url: str,
        api_endpoint: str = "http://127.0.0.1:15888",
        interval: int = 300,
        instance_name: str = "default"
    ):
        self.config_url = config_url
        self.api_endpoint = api_endpoint.rstrip('/')
        self.interval = interval
        self.instance_name = instance_name
        self.current_nodes: Set[str] = set()
        self.session = requests.Session()
    
    def run(self):
        """运行主循环"""
        logger.info(f"Starting EasyTier Node Discovery")
        logger.info(f"Config URL: {self.config_url}")
        logger.info(f"API Endpoint: {self.api_endpoint}")
        logger.info(f"Refresh Interval: {self.interval}s")
        
        # 首次立即执行
        try:
            self.sync_nodes()
        except Exception as e:
            logger.warning(f"Initial sync failed: {e}")
        
        # 定期刷新
        while True:
            time.sleep(self.interval)
            try:
                self.sync_nodes()
            except Exception as e:
                logger.warning(f"Sync failed: {e}, keeping existing nodes")
    
    def sync_nodes(self):
        """同步节点"""
        logger.debug(f"Syncing nodes from {self.config_url}")
        
        # 获取新的节点列表
        new_nodes = self.fetch_nodes()
        
        if not new_nodes:
            logger.warning("No nodes fetched, keeping existing connections")
            return
        
        # 计算差异
        to_add = new_nodes - self.current_nodes
        to_remove = self.current_nodes - new_nodes
        
        # 添加新节点
        for node_url in to_add:
            try:
                self.add_connector(node_url)
                logger.info(f"Added connector: {node_url}")
            except Exception as e:
                logger.warning(f"Failed to add connector {node_url}: {e}")
        
        # 移除旧节点
        for node_url in to_remove:
            try:
                self.remove_connector(node_url)
                logger.info(f"Removed connector: {node_url}")
            except Exception as e:
                logger.warning(f"Failed to remove connector {node_url}: {e}")
        
        # 更新当前节点列表
        self.current_nodes = new_nodes
        
        logger.info(
            f"Sync complete: added {len(to_add)}, removed {len(to_remove)}, "
            f"total {len(self.current_nodes)}"
        )
    
    def fetch_nodes(self) -> Set[str]:
        """获取节点列表"""
        parsed = urlparse(self.config_url)
        scheme = parsed.scheme.lower()
        
        if scheme in ('http', 'https'):
            return self.fetch_http_nodes()
        elif scheme == 'txt':
            return self.fetch_txt_nodes()
        elif scheme == 'srv':
            return self.fetch_srv_nodes()
        else:
            raise ValueError(f"Unsupported scheme: {scheme}")
    
    def fetch_http_nodes(self) -> Set[str]:
        """从 HTTP 服务器获取节点"""
        response = self.session.get(self.config_url)
        response.raise_for_status()
        
        nodes = set()
        for line in response.text.splitlines():
            line = line.strip()
            if line and any(line.startswith(proto) for proto in 
                          ['tcp://', 'udp://', 'ws://', 'wss://', 'quic://', 'wg://']):
                nodes.add(line)
        
        return nodes
    
    def fetch_txt_nodes(self) -> Set[str]:
        """从 DNS TXT 记录获取节点"""
        if dns is None:
            raise RuntimeError("dnspython not installed")
        
        domain = urlparse(self.config_url).hostname
        if not domain:
            raise ValueError("No host in TXT URL")
        
        answers = dns.resolver.resolve(domain, 'TXT')
        txt_data = str(answers[0]).strip('"')
        
        nodes = set()
        for part in txt_data.split():
            part = part.strip()
            if part and any(part.startswith(proto) for proto in 
                          ['tcp://', 'udp://', 'ws://', 'wss://', 'quic://', 'wg://']):
                nodes.add(part)
        
        return nodes
    
    def fetch_srv_nodes(self) -> Set[str]:
        """从 DNS SRV 记录获取节点"""
        if dns is None:
            raise RuntimeError("dnspython not installed")
        
        domain = urlparse(self.config_url).hostname
        if not domain:
            raise ValueError("No host in SRV URL")
        
        nodes = set()
        protocols = ['tcp', 'udp', 'ws', 'wss', 'quic']
        
        for protocol in protocols:
            srv_domain = f"_easytier._{protocol}.{domain}"
            try:
                answers = dns.resolver.resolve(srv_domain, 'SRV')
                for rdata in answers:
                    if rdata.port == 0:
                        continue
                    url = f"{protocol}://{rdata.target.to_text(True)}:{rdata.port}"
                    nodes.add(url)
            except dns.resolver.NXDOMAIN:
                pass  # 记录不存在，跳过
        
        return nodes
    
    def add_connector(self, node_url: str):
        """添加连接器"""
        api_url = f"{self.api_endpoint}/api/v1/instance/connector/add"
        response = self.session.post(api_url, json={"url": node_url})
        response.raise_for_status()
    
    def remove_connector(self, node_url: str):
        """移除连接器"""
        api_url = f"{self.api_endpoint}/api/v1/instance/connector/remove"
        response = self.session.post(api_url, json={"url": node_url})
        response.raise_for_status()


def main():
    parser = argparse.ArgumentParser(
        description='EasyTier Dynamic Node Discovery Script'
    )
    parser.add_argument(
        '--config-url',
        required=True,
        help='Node configuration source URL (http://, txt://, srv://)'
    )
    parser.add_argument(
        '--api-endpoint',
        default='http://127.0.0.1:15888',
        help='EasyTier API endpoint (default: http://127.0.0.1:15888)'
    )
    parser.add_argument(
        '--interval',
        type=int,
        default=300,
        help='Refresh interval in seconds (default: 300)'
    )
    parser.add_argument(
        '--instance-name',
        default='default',
        help='EasyTier instance name (default: default)'
    )
    
    args = parser.parse_args()
    
    manager = NodeDiscoveryManager(
        config_url=args.config_url,
        api_endpoint=args.api_endpoint,
        interval=args.interval,
        instance_name=args.instance_name
    )
    
    try:
        manager.run()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        sys.exit(0)


if __name__ == '__main__':
    main()
