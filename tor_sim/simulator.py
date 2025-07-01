"""
Simulation engines for modeling timing analysis attacks on Tor circuits.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set, Any
import numpy as np
import random
import time
from collections import defaultdict
import logging

from .network import Network
from .adversary import Adversary
from .circuit import Circuit, CircuitBuilder
from .timing import TimingAnalyzer, PacketStream, generate_packet_stream


@dataclass
class SimulationConfig:
    """Configuration for simulation runs."""
    # Basic parameters
    num_circuits: int = 10000
    num_clients: int = 100
    circuits_per_client: int = 100
    
    # Timing simulation
    enable_timing_analysis: bool = False
    stream_duration: float = 60.0  # seconds
    correlation_threshold: float = 0.8
    
    # Random seeds
    network_seed: Optional[int] = None
    adversary_seed: Optional[int] = None
    circuit_seed: Optional[int] = None
    
    # Output options
    save_circuits: bool = False
    save_detailed_results: bool = False
    verbose: bool = False


@dataclass
class SimulationResult:
    """Results from a simulation run."""
    # Basic metrics
    total_circuits: int = 0
    compromised_circuits: int = 0
    compromise_rate: float = 0.0
    
    # Success probability by number of circuits
    success_by_num_circuits: Dict[int, float] = field(default_factory=dict)
    
    # Detailed analysis
    guard_compromise_rate: float = 0.0
    exit_compromise_rate: float = 0.0
    both_compromise_rate: float = 0.0
    
    # Timing analysis results (if enabled)
    timing_correlation_rate: float = 0.0
    false_positive_rate: float = 0.0
    
    # Circuit statistics
    avg_circuits_per_client: float = 0.0
    unique_guards_used: int = 0
    unique_exits_used: int = 0
    
    # Network statistics
    network_size: int = 0
    adversary_node_count: int = 0
    adversary_compromise_ratio: float = 0.0
    
    # Execution metadata
    simulation_time: float = 0.0
    timestamp: float = field(default_factory=time.time)
    config: Optional[SimulationConfig] = None


class Simulator(ABC):
    """Abstract base class for simulation engines."""
    
    def __init__(self, 
                 network: Network,
                 adversary: Adversary,
                 circuit_builder: CircuitBuilder,
                 config: Optional[SimulationConfig] = None):
        self.network = network
        self.adversary = adversary
        self.circuit_builder = circuit_builder
        self.config = config or SimulationConfig()
        
        # Setup logging
        self.logger = logging.getLogger(self.__class__.__name__)
        if self.config.verbose:
            self.logger.setLevel(logging.DEBUG)
    
    @abstractmethod
    def run(self) -> SimulationResult:
        """Run the simulation and return results."""
        pass
    
    def _setup_seeds(self):
        """Setup random seeds for reproducible results."""
        if self.config.network_seed is not None:
            random.seed(self.config.network_seed)
            np.random.seed(self.config.network_seed)


class MonteCarloSimulator(Simulator):
    """Monte Carlo simulation for correlation attack analysis."""
    
    def run(self) -> SimulationResult:
        """Run Monte Carlo simulation."""
        start_time = time.time()
        self._setup_seeds()
        
        # Reset adversary state
        self.adversary.reset()
        
        # Get compromised nodes
        compromised_nodes = self.adversary.compromised_nodes(self.network)
        self.logger.info(f"Adversary controls {len(compromised_nodes)} nodes")
        
        # Build circuits
        self.logger.info("Building circuits...")
        all_circuits = self._build_circuits()
        
        # Analyze compromise
        self.logger.info("Analyzing circuit compromise...")
        results = self._analyze_circuits(all_circuits, compromised_nodes)
        
        # Calculate execution time
        execution_time = time.time() - start_time
        results.simulation_time = execution_time
        results.config = self.config
        
        self.logger.info(f"Simulation completed in {execution_time:.2f} seconds")
        self.logger.info(f"Compromise rate: {results.compromise_rate:.4f}")
        
        return results
    
    def _build_circuits(self) -> Dict[str, List[Circuit]]:
        """Build circuits for all clients."""
        if self.config.circuits_per_client > 0:
            # Multi-client simulation
            return self.circuit_builder.build_circuits_multi_client(
                self.network,
                self.config.num_clients,
                self.config.circuits_per_client
            )
        else:
            # Single batch simulation
            circuits = self.circuit_builder.build_circuits(
                self.network,
                self.config.num_circuits
            )
            return {"batch": circuits}
    
    def _analyze_circuits(self, 
                         all_circuits: Dict[str, List[Circuit]],
                         compromised_nodes: Set[str]) -> SimulationResult:
        """Analyze circuit compromise patterns."""
        results = SimulationResult()
        
        # Flatten all circuits
        flat_circuits = []
        for client_circuits in all_circuits.values():
            flat_circuits.extend(client_circuits)
        
        results.total_circuits = len(flat_circuits)
        
        if not flat_circuits:
            return results
        
        # Count compromises
        guard_compromised = 0
        exit_compromised = 0
        both_compromised = 0
        correlation_possible = 0
        
        unique_guards = set()
        unique_exits = set()
        
        for circuit in flat_circuits:
            unique_guards.add(circuit.guard.fingerprint)
            unique_exits.add(circuit.exit.fingerprint)
            
            guard_comp = circuit.guard.fingerprint in compromised_nodes
            exit_comp = circuit.exit.fingerprint in compromised_nodes
            
            if guard_comp:
                guard_compromised += 1
            if exit_comp:
                exit_compromised += 1
            if guard_comp and exit_comp:
                both_compromised += 1
            
            # Check if adversary can correlate this circuit
            if self.adversary.can_correlate_circuit(circuit, self.network):
                correlation_possible += 1
        
        # Calculate rates
        results.compromised_circuits = correlation_possible
        results.compromise_rate = correlation_possible / results.total_circuits
        results.guard_compromise_rate = guard_compromised / results.total_circuits
        results.exit_compromise_rate = exit_compromised / results.total_circuits
        results.both_compromise_rate = both_compromised / results.total_circuits
        
        # Network statistics
        results.network_size = len(self.network.nodes)
        results.adversary_node_count = len(compromised_nodes)
        results.adversary_compromise_ratio = len(compromised_nodes) / len(self.network.nodes)
        
        # Circuit statistics
        results.unique_guards_used = len(unique_guards)
        results.unique_exits_used = len(unique_exits)
        
        if all_circuits:
            results.avg_circuits_per_client = len(flat_circuits) / len(all_circuits)
        
        # Calculate success probability by number of circuits
        if len(all_circuits) > 1:
            results.success_by_num_circuits = self._calculate_success_by_circuits(
                all_circuits, compromised_nodes
            )
        
        return results
    
    def _calculate_success_by_circuits(self,
                                     all_circuits: Dict[str, List[Circuit]],
                                     compromised_nodes: Set[str]) -> Dict[int, float]:
        """Calculate attack success probability as function of circuit count."""
        success_by_count = {}
        
        # For each client, calculate cumulative success probability
        max_circuits = max(len(circuits) for circuits in all_circuits.values())
        
        for num_circuits in range(1, min(max_circuits + 1, 101)):  # Cap at 100 for performance
            successes = 0
            total_clients = 0
            
            for client_circuits in all_circuits.values():
                if len(client_circuits) >= num_circuits:
                    total_clients += 1
                    
                    # Check if adversary can correlate any of first num_circuits
                    client_compromised = False
                    for circuit in client_circuits[:num_circuits]:
                        if self.adversary.can_correlate_circuit(circuit, self.network):
                            client_compromised = True
                            break
                    
                    if client_compromised:
                        successes += 1
            
            if total_clients > 0:
                success_by_count[num_circuits] = successes / total_clients
        
        return success_by_count


class TimingSimulator(Simulator):
    """Simulation with detailed timing analysis."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.timing_analyzer = TimingAnalyzer()
    
    def run(self) -> SimulationResult:
        """Run timing-based simulation."""
        start_time = time.time()
        self._setup_seeds()
        
        if not self.config.enable_timing_analysis:
            self.logger.warning("Timing analysis disabled, falling back to Monte Carlo")
            return self._run_monte_carlo()
        
        # Reset adversary state
        self.adversary.reset()
        compromised_nodes = self.adversary.compromised_nodes(self.network)
        
        # Build circuits
        all_circuits = self._build_circuits()
        
        # Run timing analysis
        results = self._analyze_timing_correlation(all_circuits, compromised_nodes)
        
        # Calculate execution time
        execution_time = time.time() - start_time
        results.simulation_time = execution_time
        results.config = self.config
        
        return results
    
    def _run_monte_carlo(self) -> SimulationResult:
        """Fallback to Monte Carlo simulation."""
        mc_sim = MonteCarloSimulator(
            self.network, 
            self.adversary, 
            self.circuit_builder, 
            self.config
        )
        return mc_sim.run()
    
    def _analyze_timing_correlation(self,
                                   all_circuits: Dict[str, List[Circuit]],
                                   compromised_nodes: Set[str]) -> SimulationResult:
        """Analyze timing-based correlation attacks."""
        results = SimulationResult()
        
        # Flatten circuits
        flat_circuits = []
        for circuits in all_circuits.values():
            flat_circuits.extend(circuits)
        
        results.total_circuits = len(flat_circuits)
        
        if not flat_circuits:
            return results
        
        correlations_detected = 0
        false_positives = 0
        timing_analyses = 0
        
        for circuit in flat_circuits:
            # Check if adversary has necessary observation capabilities
            can_observe = self._can_observe_circuit(circuit, compromised_nodes)
            
            if can_observe:
                timing_analyses += 1
                
                # Generate synthetic traffic streams
                entry_stream = generate_packet_stream(
                    duration=self.config.stream_duration,
                    base_rate=10.0,  # packets per second
                    jitter=0.1
                )
                
                exit_stream = generate_packet_stream(
                    duration=self.config.stream_duration,
                    base_rate=10.0,
                    jitter=0.1,
                    delay=0.5  # Circuit latency
                )
                
                # Perform correlation analysis
                correlation = self.timing_analyzer.correlate_streams(
                    entry_stream, 
                    exit_stream
                )
                
                # Check if correlation exceeds threshold
                if correlation > self.config.correlation_threshold:
                    correlations_detected += 1
                    
                    # Verify if this is a true positive
                    actual_compromise = self.adversary.can_correlate_circuit(
                        circuit, self.network
                    )
                    if not actual_compromise:
                        false_positives += 1
        
        # Calculate rates
        if timing_analyses > 0:
            results.timing_correlation_rate = correlations_detected / timing_analyses
            results.false_positive_rate = false_positives / timing_analyses
        
        # Also run basic compromise analysis
        basic_compromised = sum(
            1 for circuit in flat_circuits
            if self.adversary.can_correlate_circuit(circuit, self.network)
        )
        
        results.compromised_circuits = basic_compromised
        results.compromise_rate = basic_compromised / results.total_circuits
        
        # Network statistics
        results.network_size = len(self.network.nodes)
        results.adversary_node_count = len(compromised_nodes)
        results.adversary_compromise_ratio = len(compromised_nodes) / len(self.network.nodes)
        
        return results
    
    def _can_observe_circuit(self, circuit: Circuit, compromised_nodes: Set[str]) -> bool:
        """Check if adversary can observe traffic for timing analysis."""
        # Entry observation
        entry_observable = (
            circuit.guard.fingerprint in compromised_nodes or
            self.adversary.capabilities.can_observe_isp_traffic or
            self.adversary.capabilities.can_observe_guard_traffic
        )
        
        # Exit observation  
        exit_observable = (
            circuit.exit.fingerprint in compromised_nodes or
            self.adversary.capabilities.can_observe_exit_traffic
        )
        
        return entry_observable and exit_observable


class BatchSimulator:
    """Run multiple simulations with different parameters."""
    
    def __init__(self, base_config: SimulationConfig):
        self.base_config = base_config
        self.results = []
    
    def run_parameter_sweep(self,
                           network: Network,
                           adversary_factory: callable,
                           circuit_builder: CircuitBuilder,
                           parameter_name: str,
                           parameter_values: List[Any]) -> List[SimulationResult]:
        """Run simulations sweeping over parameter values."""
        results = []
        
        for value in parameter_values:
            # Create adversary with current parameter value
            adversary = adversary_factory(**{parameter_name: value})
            
            # Create simulator
            simulator = MonteCarloSimulator(
                network, adversary, circuit_builder, self.base_config
            )
            
            # Run simulation
            result = simulator.run()
            result.parameter_name = parameter_name
            result.parameter_value = value
            results.append(result)
        
        self.results.extend(results)
        return results
    
    def run_network_size_sweep(self,
                              adversary: Adversary,
                              circuit_builder: CircuitBuilder,
                              network_sizes: List[Tuple[int, int, int]]) -> List[SimulationResult]:
        """Run simulations with different network sizes."""
        results = []
        
        for guards, middles, exits in network_sizes:
            # Generate synthetic network
            network = Network.generate_synthetic(
                num_guards=guards,
                num_middles=middles,
                num_exits=exits,
                seed=self.base_config.network_seed
            )
            
            # Reset adversary for new network
            adversary.reset()
            
            # Create simulator
            simulator = MonteCarloSimulator(
                network, adversary, circuit_builder, self.base_config
            )
            
            # Run simulation
            result = simulator.run()
            result.network_composition = (guards, middles, exits)
            results.append(result)
        
        self.results.extend(results)
        return results
