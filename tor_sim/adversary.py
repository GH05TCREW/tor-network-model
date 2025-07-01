"""
Adversary models for simulating different types of attackers.
"""

from abc import ABC, abstractmethod
from typing import Set, List, Dict, Optional, Tuple
from dataclasses import dataclass
import random
import numpy as np

from .network import Network, Node


@dataclass
class AdversaryCapabilities:
    """Defines the capabilities of an adversary."""
    # Node compromise
    can_compromise_nodes: bool = True
    max_compromised_nodes: Optional[int] = None
    
    # Traffic observation
    can_observe_isp_traffic: bool = False
    can_observe_exit_traffic: bool = False
    can_observe_guard_traffic: bool = False
    
    # Advanced capabilities
    can_perform_timing_analysis: bool = True
    can_perform_traffic_analysis: bool = False
    can_inject_traffic: bool = False
    
    # Geographic/organizational reach
    controlled_countries: Set[str] = None
    controlled_as_numbers: Set[int] = None
    
    def __post_init__(self):
        if self.controlled_countries is None:
            self.controlled_countries = set()
        if self.controlled_as_numbers is None:
            self.controlled_as_numbers = set()


class Adversary(ABC):
    """Abstract base class for adversary models."""
    
    def __init__(self, capabilities: AdversaryCapabilities):
        self.capabilities = capabilities
        self._compromised_nodes: Optional[Set[str]] = None
    
    @abstractmethod
    def compromised_nodes(self, network: Network) -> Set[str]:
        """Return the set of node fingerprints under attacker control."""
        pass
    
    def can_correlate_circuit(self, circuit: 'Circuit', network: Network) -> bool:
        """Check if adversary can perform correlation attack on a circuit."""
        compromised = self.compromised_nodes(network)
        
        # Check if adversary controls both entry and exit
        entry_compromised = circuit.guard.fingerprint in compromised
        exit_compromised = circuit.exit.fingerprint in compromised
        
        # Basic correlation requires control of entry and exit
        if entry_compromised and exit_compromised:
            return True
        
        # Advanced adversaries might have other capabilities
        if self.capabilities.can_observe_isp_traffic and exit_compromised:
            return True
        
        if self.capabilities.can_observe_exit_traffic and entry_compromised:
            return True
        
        return False
    
    def correlation_probability(self, circuit: 'Circuit', network: Network) -> float:
        """Return probability of successful correlation for this circuit."""
        if self.can_correlate_circuit(circuit, network):
            return 1.0
        return 0.0
    
    def reset(self) -> None:
        """Reset adversary state (e.g., for new simulation run)."""
        self._compromised_nodes = None


class RandomAdversary(Adversary):
    """Adversary that randomly compromises nodes."""
    
    def __init__(self, 
                 num_compromised: int,
                 capabilities: Optional[AdversaryCapabilities] = None,
                 seed: Optional[int] = None):
        if capabilities is None:
            capabilities = AdversaryCapabilities()
        
        super().__init__(capabilities)
        self.num_compromised = num_compromised
        self.seed = seed
        
        if seed is not None:
            random.seed(seed)
            np.random.seed(seed)
    
    def compromised_nodes(self, network: Network) -> Set[str]:
        """Randomly select nodes to compromise."""
        if self._compromised_nodes is None:
            all_nodes = list(network.nodes.keys())
            
            # Ensure we don't try to compromise more nodes than exist
            num_to_compromise = min(self.num_compromised, len(all_nodes))
            
            compromised = set(random.sample(all_nodes, num_to_compromise))
            self._compromised_nodes = compromised
        
        return self._compromised_nodes


class ASLevelAdversary(Adversary):
    """Adversary that controls nodes in specific Autonomous Systems."""
    
    def __init__(self,
                 controlled_as_numbers: List[int],
                 capabilities: Optional[AdversaryCapabilities] = None):
        if capabilities is None:
            capabilities = AdversaryCapabilities()
        
        capabilities.controlled_as_numbers = set(controlled_as_numbers)
        super().__init__(capabilities)
        self.controlled_as_numbers = controlled_as_numbers
    
    def compromised_nodes(self, network: Network) -> Set[str]:
        """Compromise all nodes in controlled AS numbers."""
        if self._compromised_nodes is None:
            compromised = set()
            
            for node in network.nodes.values():
                if node.as_number in self.controlled_as_numbers:
                    compromised.add(node.fingerprint)
            
            self._compromised_nodes = compromised
        
        return self._compromised_nodes


class CountryLevelAdversary(Adversary):
    """Adversary that controls nodes in specific countries."""
    
    def __init__(self,
                 controlled_countries: List[str],
                 capabilities: Optional[AdversaryCapabilities] = None):
        if capabilities is None:
            capabilities = AdversaryCapabilities()
        
        capabilities.controlled_countries = set(controlled_countries)
        super().__init__(capabilities)
        self.controlled_countries = controlled_countries
    
    def compromised_nodes(self, network: Network) -> Set[str]:
        """Compromise all nodes in controlled countries."""
        if self._compromised_nodes is None:
            compromised = set()
            
            for node in network.nodes.values():
                if node.country_code in self.controlled_countries:
                    compromised.add(node.fingerprint)
            
            self._compromised_nodes = compromised
        
        return self._compromised_nodes


class GPAAdversary(Adversary):
    """Global Passive Adversary with extensive monitoring capabilities."""
    
    def __init__(self,
                 node_compromise_ratio: float = 0.1,
                 capabilities: Optional[AdversaryCapabilities] = None):
        if capabilities is None:
            capabilities = AdversaryCapabilities(
                can_observe_isp_traffic=True,
                can_observe_exit_traffic=True,
                can_observe_guard_traffic=True,
                can_perform_timing_analysis=True,
                can_perform_traffic_analysis=True
            )
        
        super().__init__(capabilities)
        self.node_compromise_ratio = node_compromise_ratio
    
    def compromised_nodes(self, network: Network) -> Set[str]:
        """Compromise a fraction of all nodes."""
        if self._compromised_nodes is None:
            all_nodes = list(network.nodes.keys())
            num_to_compromise = int(len(all_nodes) * self.node_compromise_ratio)
            
            compromised = set(random.sample(all_nodes, num_to_compromise))
            self._compromised_nodes = compromised
        
        return self._compromised_nodes
    
    def correlation_probability(self, circuit: 'Circuit', network: Network) -> float:
        """GPA has higher correlation probability due to traffic observation."""
        compromised = self.compromised_nodes(network)
        
        # Direct node compromise
        if (circuit.guard.fingerprint in compromised and 
            circuit.exit.fingerprint in compromised):
            return 1.0
        
        # Partial compromise with traffic observation
        guard_compromised = circuit.guard.fingerprint in compromised
        exit_compromised = circuit.exit.fingerprint in compromised
        
        if guard_compromised or exit_compromised:
            # Probability depends on traffic analysis capabilities
            return 0.8 if self.capabilities.can_perform_traffic_analysis else 0.3
        
        # Pure traffic analysis without node compromise
        if (self.capabilities.can_observe_isp_traffic and 
            self.capabilities.can_observe_exit_traffic):
            return 0.1  # Low but non-zero probability
        
        return 0.0


class HybridAdversary(Adversary):
    """Combines multiple adversary types."""
    
    def __init__(self,
                 random_nodes: int = 0,
                 controlled_countries: Optional[List[str]] = None,
                 controlled_as_numbers: Optional[List[int]] = None,
                 capabilities: Optional[AdversaryCapabilities] = None):
        if capabilities is None:
            capabilities = AdversaryCapabilities()
        
        super().__init__(capabilities)
        self.random_nodes = random_nodes
        self.controlled_countries = controlled_countries or []
        self.controlled_as_numbers = controlled_as_numbers or []
    
    def compromised_nodes(self, network: Network) -> Set[str]:
        """Combine multiple compromise strategies."""
        if self._compromised_nodes is None:
            compromised = set()
            
            # Random node compromise
            if self.random_nodes > 0:
                all_nodes = list(network.nodes.keys())
                num_random = min(self.random_nodes, len(all_nodes))
                compromised.update(random.sample(all_nodes, num_random))
            
            # Country-based compromise
            for node in network.nodes.values():
                if node.country_code in self.controlled_countries:
                    compromised.add(node.fingerprint)
            
            # AS-based compromise
            for node in network.nodes.values():
                if node.as_number in self.controlled_as_numbers:
                    compromised.add(node.fingerprint)
            
            self._compromised_nodes = compromised
        
        return self._compromised_nodes


class StrategyAdversary(Adversary):
    """Adversary with specific targeting strategies."""
    
    def __init__(self,
                 strategy: str = "high_bandwidth",
                 num_nodes: int = 50,
                 capabilities: Optional[AdversaryCapabilities] = None):
        if capabilities is None:
            capabilities = AdversaryCapabilities()
        
        super().__init__(capabilities)
        self.strategy = strategy
        self.num_nodes = num_nodes
    
    def compromised_nodes(self, network: Network) -> Set[str]:
        """Strategically select nodes to compromise."""
        if self._compromised_nodes is None:
            compromised = set()
            
            if self.strategy == "high_bandwidth":
                # Target highest bandwidth nodes
                sorted_nodes = sorted(
                    network.nodes.values(),
                    key=lambda n: n.effective_bandwidth,
                    reverse=True
                )
                compromised.update(
                    node.fingerprint for node in sorted_nodes[:self.num_nodes]
                )
            
            elif self.strategy == "guards_and_exits":
                # Preferentially target guards and exits
                guards = network.guard_nodes
                exits = network.exit_nodes
                
                # Split budget between guards and exits
                num_guards = min(self.num_nodes // 2, len(guards))
                num_exits = min(self.num_nodes - num_guards, len(exits))
                
                target_guards = random.sample(guards, num_guards)
                target_exits = random.sample(exits, num_exits)
                
                compromised.update(node.fingerprint for node in target_guards)
                compromised.update(node.fingerprint for node in target_exits)
            
            elif self.strategy == "geographic_spread":
                # Distribute across many countries
                country_nodes = {}
                for node in network.nodes.values():
                    country = node.country_code or "Unknown"
                    if country not in country_nodes:
                        country_nodes[country] = []
                    country_nodes[country].append(node)
                
                # Select nodes from different countries
                nodes_per_country = max(1, self.num_nodes // len(country_nodes))
                for country_node_list in country_nodes.values():
                    sample_size = min(nodes_per_country, len(country_node_list))
                    selected = random.sample(country_node_list, sample_size)
                    compromised.update(node.fingerprint for node in selected)
                    
                    if len(compromised) >= self.num_nodes:
                        break
            
            self._compromised_nodes = compromised
        
        return self._compromised_nodes


# Factory function for creating adversaries
def create_adversary(adversary_type: str, **kwargs) -> Adversary:
    """Factory function to create adversary instances."""
    adversary_types = {
        "random": RandomAdversary,
        "as_level": ASLevelAdversary,
        "country_level": CountryLevelAdversary,
        "gpa": GPAAdversary,
        "hybrid": HybridAdversary,
        "strategic": StrategyAdversary,
    }
    
    if adversary_type not in adversary_types:
        raise ValueError(f"Unknown adversary type: {adversary_type}")
    
    return adversary_types[adversary_type](**kwargs)
