"""
Tor Network Model - A research toolkit for modeling timing analysis attacks on Tor networks.

This package provides tools for:
- Simulating Tor network topologies
- Modeling various adversary capabilities
- Analyzing correlation attacks and timing analysis
- Visualizing attack success rates and network vulnerabilities
"""

__version__ = "0.1.0"
__author__ = "Masic"

from .network import Network, Node
from .adversary import (
    Adversary, RandomAdversary, ASLevelAdversary, CountryLevelAdversary, 
    GPAAdversary, HybridAdversary, StrategyAdversary
)
from .circuit import CircuitBuilder, Circuit, CircuitConstraints, PathSelectionPolicy
from .simulator import MonteCarloSimulator, TimingSimulator, BatchSimulator, SimulationConfig, SimulationResult
from .visualization import Visualizer

__all__ = [
    "Network",
    "Node", 
    "Adversary",
    "RandomAdversary",
    "ASLevelAdversary",
    "CountryLevelAdversary", 
    "GPAAdversary",
    "HybridAdversary",
    "StrategyAdversary",
    "CircuitBuilder",
    "Circuit",
    "CircuitConstraints",
    "PathSelectionPolicy",
    "MonteCarloSimulator",
    "TimingSimulator",
    "BatchSimulator",
    "SimulationConfig",
    "SimulationResult",
    "Visualizer",
]
