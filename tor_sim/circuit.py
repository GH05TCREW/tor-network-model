"""
Circuit building and path selection for Tor network simulation.
"""

from dataclasses import dataclass
from typing import List, Optional, Set, Tuple, Dict
import random
import numpy as np
from enum import Enum

from .network import Network, Node, NodeType


class PathSelectionPolicy(Enum):
    """Different path selection policies."""
    BANDWIDTH_WEIGHTED = "bandwidth_weighted"
    UNIFORM_RANDOM = "uniform_random"
    CONSENSUS_WEIGHTS = "consensus_weights"


@dataclass
class CircuitConstraints:
    """Constraints for circuit construction."""
    # Geographic diversity
    require_different_countries: bool = True
    require_different_as: bool = True
    max_same_country: int = 1
    
    # Node diversity
    require_different_operators: bool = True
    avoid_same_subnet: bool = True
    
    # Excluded nodes/countries/AS
    excluded_countries: Set[str] = None
    excluded_as_numbers: Set[int] = None
    excluded_nodes: Set[str] = None
    
    # Guard selection policy
    use_persistent_guards: bool = True
    num_guard_nodes: int = 3
    
    def __post_init__(self):
        if self.excluded_countries is None:
            self.excluded_countries = set()
        if self.excluded_as_numbers is None:
            self.excluded_as_numbers = set()
        if self.excluded_nodes is None:
            self.excluded_nodes = set()


@dataclass
class Circuit:
    """Represents a Tor circuit (3-hop path)."""
    guard: Node
    middle: Node
    exit: Node
    
    # Metadata
    created_at: Optional[float] = None
    circuit_id: Optional[str] = None
    
    @property
    def nodes(self) -> List[Node]:
        """Get all nodes in the circuit."""
        return [self.guard, self.middle, self.exit]
    
    @property
    def fingerprints(self) -> List[str]:
        """Get fingerprints of all nodes in the circuit."""
        return [node.fingerprint for node in self.nodes]
    
    @property
    def countries(self) -> List[Optional[str]]:
        """Get countries of all nodes."""
        return [node.country_code for node in self.nodes]
    
    @property
    def as_numbers(self) -> List[Optional[int]]:
        """Get AS numbers of all nodes."""
        return [node.as_number for node in self.nodes]
    
    def has_geographic_diversity(self) -> bool:
        """Check if circuit has geographic diversity."""
        countries = [c for c in self.countries if c is not None]
        return len(set(countries)) == len(countries)
    
    def has_as_diversity(self) -> bool:
        """Check if circuit has AS-level diversity."""
        as_numbers = [a for a in self.as_numbers if a is not None]
        return len(set(as_numbers)) == len(as_numbers)
    
    def __str__(self) -> str:
        return f"Circuit({self.guard.nickname} -> {self.middle.nickname} -> {self.exit.nickname})"


class CircuitBuilder:
    """Builds Tor circuits according to specified policies and constraints."""
    
    def __init__(self,
                 constraints: Optional[CircuitConstraints] = None,
                 path_selection: PathSelectionPolicy = PathSelectionPolicy.BANDWIDTH_WEIGHTED,
                 seed: Optional[int] = None):
        self.constraints = constraints or CircuitConstraints()
        self.path_selection = path_selection
        
        # Persistent guard nodes for clients
        self._client_guards: Dict[str, List[Node]] = {}
        
        if seed is not None:
            random.seed(seed)
            np.random.seed(seed)
    
    def select_guard_nodes(self, client_id: str, network: Network) -> List[Node]:
        """Select persistent guard nodes for a client."""
        if client_id not in self._client_guards:
            available_guards = self._filter_nodes(
                network.guard_nodes, 
                network,
                exclude_fingerprints=set()
            )
            
            if len(available_guards) < self.constraints.num_guard_nodes:
                # Not enough guards available, use what we have
                selected_guards = available_guards
            else:
                # Select guards using bandwidth weighting
                weights = network.get_bandwidth_weights(available_guards)
                selected_guards = list(np.random.choice(
                    available_guards,
                    size=self.constraints.num_guard_nodes,
                    replace=False,
                    p=weights
                ))
            
            self._client_guards[client_id] = selected_guards
        
        return self._client_guards[client_id]
    
    def _filter_nodes(self,
                     nodes: List[Node],
                     network: Network,
                     exclude_fingerprints: Set[str],
                     selected_nodes: Optional[List[Node]] = None) -> List[Node]:
        """Filter nodes based on constraints."""
        filtered = []
        
        for node in nodes:
            # Skip excluded nodes
            if node.fingerprint in exclude_fingerprints:
                continue
            if node.fingerprint in self.constraints.excluded_nodes:
                continue
            if node.country_code in self.constraints.excluded_countries:
                continue
            if node.as_number in self.constraints.excluded_as_numbers:
                continue
            
            # Check diversity constraints if we already have selected nodes
            if selected_nodes:
                if self.constraints.require_different_countries:
                    selected_countries = [n.country_code for n in selected_nodes]
                    if node.country_code in selected_countries:
                        continue
                
                if self.constraints.require_different_as:
                    selected_as = [n.as_number for n in selected_nodes]
                    if node.as_number in selected_as:
                        continue
            
            filtered.append(node)
        
        return filtered
    
    def _select_node_weighted(self, 
                             nodes: List[Node],
                             network: Network) -> Optional[Node]:
        """Select a node using bandwidth weighting."""
        if not nodes:
            return None
        
        if self.path_selection == PathSelectionPolicy.UNIFORM_RANDOM:
            return random.choice(nodes)
        
        elif self.path_selection == PathSelectionPolicy.BANDWIDTH_WEIGHTED:
            weights = network.get_bandwidth_weights(nodes)
            return np.random.choice(nodes, p=weights)
        
        else:  # CONSENSUS_WEIGHTS - fallback to bandwidth for now
            weights = network.get_bandwidth_weights(nodes)
            return np.random.choice(nodes, p=weights)
    
    def build_circuit(self,
                     network: Network,
                     client_id: str = "default") -> Optional[Circuit]:
        """Build a single circuit for a client."""
        selected_nodes = []
        used_fingerprints = set()
        
        # 1. Select guard node
        if self.constraints.use_persistent_guards:
            available_guards = self.select_guard_nodes(client_id, network)
            if not available_guards:
                return None
            guard = random.choice(available_guards)
        else:
            available_guards = self._filter_nodes(
                network.guard_nodes,
                network, 
                used_fingerprints
            )
            guard = self._select_node_weighted(available_guards, network)
            if not guard:
                return None
        
        selected_nodes.append(guard)
        used_fingerprints.add(guard.fingerprint)
        
        # 2. Select middle node
        available_middles = self._filter_nodes(
            network.middle_nodes,
            network,
            used_fingerprints,
            selected_nodes
        )
        middle = self._select_node_weighted(available_middles, network)
        if not middle:
            return None
        
        selected_nodes.append(middle)
        used_fingerprints.add(middle.fingerprint)
        
        # 3. Select exit node
        available_exits = self._filter_nodes(
            network.exit_nodes,
            network,
            used_fingerprints,
            selected_nodes
        )
        exit_node = self._select_node_weighted(available_exits, network)
        if not exit_node:
            return None
        
        return Circuit(
            guard=guard,
            middle=middle,
            exit=exit_node,
            circuit_id=f"{client_id}_{len(selected_nodes)}"
        )
    
    def build_circuits(self,
                      network: Network,
                      num_circuits: int,
                      client_id: str = "default") -> List[Circuit]:
        """Build multiple circuits for a client."""
        circuits = []
        
        for i in range(num_circuits):
            circuit = self.build_circuit(network, f"{client_id}_{i}")
            if circuit:
                circuits.append(circuit)
        
        return circuits
    
    def build_circuits_multi_client(self,
                                   network: Network,
                                   num_clients: int,
                                   circuits_per_client: int) -> Dict[str, List[Circuit]]:
        """Build circuits for multiple clients."""
        all_circuits = {}
        
        for client_id in range(num_clients):
            client_name = f"client_{client_id}"
            circuits = self.build_circuits(
                network,
                circuits_per_client,
                client_name
            )
            all_circuits[client_name] = circuits
        
        return all_circuits
    
    def get_circuit_statistics(self, circuits: List[Circuit]) -> Dict[str, float]:
        """Calculate statistics about circuit diversity."""
        if not circuits:
            return {}
        
        stats = {
            "total_circuits": len(circuits),
            "geographic_diversity_rate": 0.0,
            "as_diversity_rate": 0.0,
            "unique_guards": 0,
            "unique_exits": 0,
            "avg_guard_bandwidth": 0.0,
            "avg_exit_bandwidth": 0.0,
        }
        
        # Calculate diversity rates
        geo_diverse = sum(1 for c in circuits if c.has_geographic_diversity())
        as_diverse = sum(1 for c in circuits if c.has_as_diversity())
        
        stats["geographic_diversity_rate"] = geo_diverse / len(circuits)
        stats["as_diversity_rate"] = as_diverse / len(circuits)
        
        # Count unique nodes
        unique_guards = set(c.guard.fingerprint for c in circuits)
        unique_exits = set(c.exit.fingerprint for c in circuits)
        
        stats["unique_guards"] = len(unique_guards)
        stats["unique_exits"] = len(unique_exits)
        
        # Calculate average bandwidths
        guard_bw = [c.guard.effective_bandwidth for c in circuits]
        exit_bw = [c.exit.effective_bandwidth for c in circuits]
        
        if guard_bw:
            stats["avg_guard_bandwidth"] = sum(guard_bw) / len(guard_bw)
        if exit_bw:
            stats["avg_exit_bandwidth"] = sum(exit_bw) / len(exit_bw)
        
        return stats
    
    def reset_client_state(self, client_id: Optional[str] = None) -> None:
        """Reset persistent state for a client (or all clients)."""
        if client_id:
            self._client_guards.pop(client_id, None)
        else:
            self._client_guards.clear()


# Utility functions
def analyze_circuit_security(circuit: Circuit, network: Network) -> Dict[str, any]:
    """Analyze security properties of a circuit."""
    analysis = {
        "geographic_diversity": circuit.has_geographic_diversity(),
        "as_diversity": circuit.has_as_diversity(),
        "countries": circuit.countries,
        "as_numbers": circuit.as_numbers,
        "total_bandwidth": sum(node.effective_bandwidth for node in circuit.nodes),
        "weakest_link_bandwidth": min(node.effective_bandwidth for node in circuit.nodes),
    }
    
    # Check for potential issues
    issues = []
    
    if not circuit.has_geographic_diversity():
        issues.append("Multiple nodes in same country")
    
    if not circuit.has_as_diversity():
        issues.append("Multiple nodes in same AS")
    
    # Check for suspicious countries (example)
    suspicious_countries = {"XX", "ZZ"}  # Placeholder
    circuit_countries = set(c for c in circuit.countries if c)
    if circuit_countries.intersection(suspicious_countries):
        issues.append("Circuit includes suspicious countries")
    
    analysis["security_issues"] = issues
    analysis["security_score"] = max(0, 10 - len(issues))
    
    return analysis


def simulate_circuit_failures(circuits: List[Circuit],
                             failure_rate: float = 0.1) -> List[Circuit]:
    """Simulate random circuit failures."""
    surviving_circuits = []
    
    for circuit in circuits:
        if random.random() > failure_rate:
            surviving_circuits.append(circuit)
    
    return surviving_circuits
