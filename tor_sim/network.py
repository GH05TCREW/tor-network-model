"""
Network module for representing Tor network topology and nodes.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple
from enum import Enum
import networkx as nx
import numpy as np
import json
import random
from pathlib import Path


class NodeType(Enum):
    """Types of Tor nodes."""
    GUARD = "guard"
    MIDDLE = "middle"
    EXIT = "exit"


class NodeFlag(Enum):
    """Tor node flags."""
    AUTHORITY = "Authority"
    BAD_EXIT = "BadExit"
    EXIT = "Exit"
    FAST = "Fast"
    GUARD = "Guard"
    HSDIR = "HSDir"
    NAMED = "Named"
    RUNNING = "Running"
    STABLE = "Stable"
    UNNAMED = "Unnamed"
    VALID = "Valid"
    V2DIR = "V2Dir"


@dataclass
class Node:
    """Represents a Tor relay node."""
    fingerprint: str
    nickname: str
    address: str
    or_port: int
    dir_port: Optional[int] = None
    
    # Network properties
    bandwidth: int = 0  # KB/s
    observed_bandwidth: int = 0  # KB/s
    advertised_bandwidth: int = 0  # KB/s
    
    # Geographic and AS information
    country_code: Optional[str] = None
    as_number: Optional[int] = None
    as_name: Optional[str] = None
    
    # Node capabilities and flags
    flags: Set[NodeFlag] = field(default_factory=set)
    exit_policy: List[str] = field(default_factory=list)
    
    # Consensus information
    published: Optional[str] = None
    uptime: int = 0  # seconds
    
    def __post_init__(self):
        """Post-initialization processing."""
        if isinstance(self.flags, list):
            self.flags = set(self.flags)
    
    @property
    def is_guard(self) -> bool:
        """Check if node can be used as guard."""
        return NodeFlag.GUARD in self.flags and NodeFlag.RUNNING in self.flags
    
    @property 
    def is_exit(self) -> bool:
        """Check if node can be used as exit."""
        return (NodeFlag.EXIT in self.flags and 
                NodeFlag.RUNNING in self.flags and
                NodeFlag.BAD_EXIT not in self.flags)
    
    @property
    def is_middle(self) -> bool:
        """Check if node can be used as middle relay."""
        return (NodeFlag.RUNNING in self.flags and
                NodeFlag.VALID in self.flags)
    
    @property
    def effective_bandwidth(self) -> int:
        """Get the effective bandwidth for path selection."""
        if self.observed_bandwidth > 0:
            return min(self.observed_bandwidth, self.advertised_bandwidth)
        return self.advertised_bandwidth


class Network:
    """Represents the Tor network topology and provides analysis methods."""
    
    def __init__(self):
        self.nodes: Dict[str, Node] = {}
        self.graph = nx.Graph()
        self._guard_nodes: Optional[List[Node]] = None
        self._middle_nodes: Optional[List[Node]] = None
        self._exit_nodes: Optional[List[Node]] = None
        
    def add_node(self, node: Node) -> None:
        """Add a node to the network."""
        self.nodes[node.fingerprint] = node
        self.graph.add_node(node.fingerprint, node=node)
        # Clear cached node lists
        self._guard_nodes = None
        self._middle_nodes = None
        self._exit_nodes = None
    
    def remove_node(self, fingerprint: str) -> None:
        """Remove a node from the network."""
        if fingerprint in self.nodes:
            del self.nodes[fingerprint]
            self.graph.remove_node(fingerprint)
            # Clear cached node lists
            self._guard_nodes = None
            self._middle_nodes = None
            self._exit_nodes = None
    
    @property
    def guard_nodes(self) -> List[Node]:
        """Get all guard nodes."""
        if self._guard_nodes is None:
            self._guard_nodes = [node for node in self.nodes.values() if node.is_guard]
        return self._guard_nodes
    
    @property
    def middle_nodes(self) -> List[Node]:
        """Get all middle relay nodes."""
        if self._middle_nodes is None:
            self._middle_nodes = [node for node in self.nodes.values() if node.is_middle]
        return self._middle_nodes
    
    @property
    def exit_nodes(self) -> List[Node]:
        """Get all exit nodes."""
        if self._exit_nodes is None:
            self._exit_nodes = [node for node in self.nodes.values() if node.is_exit]
        return self._exit_nodes
    
    def get_nodes_by_type(self, node_type: NodeType) -> List[Node]:
        """Get nodes by type."""
        if node_type == NodeType.GUARD:
            return self.guard_nodes
        elif node_type == NodeType.MIDDLE:
            return self.middle_nodes
        elif node_type == NodeType.EXIT:
            return self.exit_nodes
        else:
            raise ValueError(f"Unknown node type: {node_type}")
    
    def get_nodes_by_country(self, country_code: str) -> List[Node]:
        """Get all nodes in a specific country."""
        return [node for node in self.nodes.values() 
                if node.country_code == country_code]
    
    def get_nodes_by_as(self, as_number: int) -> List[Node]:
        """Get all nodes in a specific Autonomous System."""
        return [node for node in self.nodes.values()
                if node.as_number == as_number]
    
    def get_bandwidth_weights(self, nodes: List[Node]) -> np.ndarray:
        """Get bandwidth-based selection weights for nodes."""
        if not nodes:
            return np.array([])
        
        bandwidths = np.array([node.effective_bandwidth for node in nodes])
        # Avoid division by zero
        if bandwidths.sum() == 0:
            return np.ones(len(nodes)) / len(nodes)
        
        return bandwidths / bandwidths.sum()
    
    def sample_node(self, nodes: List[Node], weights: Optional[np.ndarray] = None) -> Node:
        """Sample a node from the given list using bandwidth weighting."""
        if not nodes:
            raise ValueError("Cannot sample from empty node list")
        
        if weights is None:
            weights = self.get_bandwidth_weights(nodes)
        
        return np.random.choice(nodes, p=weights)
    
    def get_country_distribution(self) -> Dict[str, int]:
        """Get distribution of nodes by country."""
        country_counts = {}
        for node in self.nodes.values():
            country = node.country_code or "Unknown"
            country_counts[country] = country_counts.get(country, 0) + 1
        return country_counts
    
    def get_as_distribution(self) -> Dict[int, int]:
        """Get distribution of nodes by AS."""
        as_counts = {}
        for node in self.nodes.values():
            as_num = node.as_number
            if as_num is not None:
                as_counts[as_num] = as_counts.get(as_num, 0) + 1
        return as_counts
    
    @classmethod
    def from_consensus(cls, consensus_path: str) -> 'Network':
        """Load network from Tor consensus file."""
        # This would integrate with stem library to parse real consensus
        # For now, we'll create a placeholder implementation
        network = cls()
        
        # TODO: Implement real consensus parsing using stem
        # from stem.descriptor import parse_file
        # for desc in parse_file(consensus_path):
        #     node = Node.from_descriptor(desc)
        #     network.add_node(node)
        
        return network
    
    @classmethod
    def generate_synthetic(cls, 
                          num_guards: int = 100,
                          num_middles: int = 1000, 
                          num_exits: int = 200,
                          countries: Optional[List[str]] = None,
                          seed: Optional[int] = None) -> 'Network':
        """Generate a synthetic Tor network for testing."""
        if seed is not None:
            random.seed(seed)
            np.random.seed(seed)
        
        if countries is None:
            countries = ["US", "DE", "FR", "NL", "GB", "CA", "SE", "CH", "AT", "RU"]
        
        network = cls()
        
        # Generate guard nodes
        for i in range(num_guards):
            node = Node(
                fingerprint=f"guard_{i:04d}",
                nickname=f"Guard{i:04d}",
                address=f"192.168.1.{i % 255}",
                or_port=9001,
                bandwidth=random.randint(1000, 10000),  # KB/s
                observed_bandwidth=random.randint(500, 5000),
                advertised_bandwidth=random.randint(1000, 10000),
                country_code=random.choice(countries),
                as_number=random.randint(1000, 65000),
                flags={NodeFlag.GUARD, NodeFlag.RUNNING, NodeFlag.VALID, NodeFlag.STABLE}
            )
            network.add_node(node)
        
        # Generate middle nodes  
        for i in range(num_middles):
            node = Node(
                fingerprint=f"middle_{i:04d}",
                nickname=f"Middle{i:04d}",
                address=f"10.0.{i // 255}.{i % 255}",
                or_port=9001,
                bandwidth=random.randint(500, 5000),
                observed_bandwidth=random.randint(250, 2500),
                advertised_bandwidth=random.randint(500, 5000),
                country_code=random.choice(countries),
                as_number=random.randint(1000, 65000),
                flags={NodeFlag.RUNNING, NodeFlag.VALID}
            )
            network.add_node(node)
        
        # Generate exit nodes
        for i in range(num_exits):
            node = Node(
                fingerprint=f"exit_{i:04d}",
                nickname=f"Exit{i:04d}",
                address=f"172.16.{i // 255}.{i % 255}",
                or_port=9001,
                bandwidth=random.randint(2000, 20000),
                observed_bandwidth=random.randint(1000, 10000),
                advertised_bandwidth=random.randint(2000, 20000),
                country_code=random.choice(countries),
                as_number=random.randint(1000, 65000),
                flags={NodeFlag.EXIT, NodeFlag.RUNNING, NodeFlag.VALID}
            )
            network.add_node(node)
            
        return network
    
    def to_json(self, filepath: str) -> None:
        """Save network to JSON file."""
        data = {
            "nodes": {
                fp: {
                    "fingerprint": node.fingerprint,
                    "nickname": node.nickname,
                    "address": node.address,
                    "or_port": node.or_port,
                    "dir_port": node.dir_port,
                    "bandwidth": node.bandwidth,
                    "observed_bandwidth": node.observed_bandwidth,
                    "advertised_bandwidth": node.advertised_bandwidth,
                    "country_code": node.country_code,
                    "as_number": node.as_number,
                    "as_name": node.as_name,
                    "flags": [flag.value for flag in node.flags],
                    "exit_policy": node.exit_policy,
                    "published": node.published,
                    "uptime": node.uptime
                }
                for fp, node in self.nodes.items()
            }
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    @classmethod
    def from_json(cls, filepath: str) -> 'Network':
        """Load network from JSON file."""
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        network = cls()
        for node_data in data["nodes"].values():
            flags = {NodeFlag(flag) for flag in node_data["flags"]}
            node = Node(
                fingerprint=node_data["fingerprint"],
                nickname=node_data["nickname"],
                address=node_data["address"],
                or_port=node_data["or_port"],
                dir_port=node_data.get("dir_port"),
                bandwidth=node_data["bandwidth"],
                observed_bandwidth=node_data["observed_bandwidth"],
                advertised_bandwidth=node_data["advertised_bandwidth"],
                country_code=node_data.get("country_code"),
                as_number=node_data.get("as_number"),
                as_name=node_data.get("as_name"),
                flags=flags,
                exit_policy=node_data.get("exit_policy", []),
                published=node_data.get("published"),
                uptime=node_data.get("uptime", 0)
            )
            network.add_node(node)
        
        return network
    
    def __len__(self) -> int:
        """Return total number of nodes."""
        return len(self.nodes)
    
    def __str__(self) -> str:
        """String representation of the network."""
        return (f"Network(nodes={len(self.nodes)}, "
                f"guards={len(self.guard_nodes)}, "
                f"middles={len(self.middle_nodes)}, "
                f"exits={len(self.exit_nodes)})")
