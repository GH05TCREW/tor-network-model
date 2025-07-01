# Tor Network Model - Research Toolkit

A Python toolkit for modeling and analyzing timing-based correlation attacks on the Tor network. This package provides modular components for simulating different adversary models, network topologies, and attack scenarios.

## Overview

The Tor network provides anonymity through a three-hop circuit design (guard → middle → exit), but sophisticated adversaries can potentially perform correlation attacks by controlling multiple nodes or observing network traffic. This toolkit enables researchers to:

- Model various adversary capabilities (random compromise, AS-level control, global passive adversary)
- Simulate realistic Tor circuit construction with geographic and bandwidth constraints
- Analyze timing-based correlation attacks through Monte Carlo simulation
- Visualize attack success rates and network vulnerability patterns
- Explore defensive measures and their effectiveness

## Key Features

### Network Modeling
- **Synthetic network generation** with configurable node distributions
- **Geographic and AS diversity** modeling for realistic constraints
- **Bandwidth-weighted path selection** following Tor specifications

### Adversary Models
- **RandomAdversary**: Controls a fixed number of randomly selected nodes
- **ASLevelAdversary**: Controls nodes within specific Autonomous Systems
- **CountryLevelAdversary**: Controls nodes in specific countries (e.g., Five Eyes)
- **GPAAdversary**: Global Passive Adversary with extensive monitoring capabilities
- **HybridAdversary**: Combines multiple compromise strategies

### Circuit Analysis
- **Realistic circuit building** with guard stickiness and diversity constraints
- **Path selection policies** including bandwidth weighting and geographic exclusion
- **Security analysis** for individual circuits and client patterns
- **Failure simulation** for robustness testing

### Attack Simulation
- **Monte Carlo simulation** for statistical analysis of attack success rates
- **Timing analysis** with packet-level correlation
- **Parameter sweeps** to explore adversary strength vs success probability
- **Multi-client scenarios** with realistic usage patterns

### Visualization
- **Interactive plots** showing attack success vs adversary size
- **Geographic risk analysis** highlighting vulnerable regions
- **Network topology visualization** with compromised nodes highlighted
- **Statistical dashboards** for comprehensive analysis

## Installation

### From Source
```bash
git clone https://github.com/GH05TCREW/tor-network-model.git
cd tor-network-model
pip install -e .
```

### Requirements
- Python 3.8+
- NumPy, SciPy, pandas
- NetworkX for graph analysis
- Plotly for interactive visualization
- Jupyter for notebook interface
- Click for CLI interface

## Quick Start

### Command Line Interface

Generate a synthetic network:
```bash
tor-sim generate-network --synthetic --guards 200 --middles 2000 --exits 400 --output network.json
```

Run a simulation:
```bash
tor-sim simulate --network network.json --adversary random --num-compromised 100 --circuits 50000 --output results.json
```

Parameter sweep analysis:
```bash
tor-sim sweep --network network.json --adversary random --min-value 25 --max-value 200 --steps 8 --plot
```

### Python API

```python
from tor_sim import (
    Network, RandomAdversary, CircuitBuilder, 
    MonteCarloSimulator, SimulationConfig, Visualizer
)

# Generate network
network = Network.generate_synthetic(
    num_guards=200, num_middles=2000, num_exits=400, seed=42
)

# Create adversary
adversary = RandomAdversary(num_compromised=100, seed=42)

# Build circuits
builder = CircuitBuilder()
config = SimulationConfig(num_circuits=50000)

# Run simulation
simulator = MonteCarloSimulator(network, adversary, builder, config)
result = simulator.run()

print(f"Attack success rate: {result.compromise_rate:.4f}")

# Visualize results
visualizer = Visualizer()
fig = visualizer.plot_compromise_rate_vs_adversary_size([result])
fig.show()
```

### Jupyter Notebooks

Interactive analysis with widgets and live plotting:

```python
# See notebooks/tor_analysis_demo.ipynb for examples
# Includes parameter sweeps, adversary comparisons, and interactive widgets
```

## Architecture

The toolkit design:

```
┌──────────────────┐     ┌─────────────────────┐     ┌──────────────────┐
│  Configuration   │──►  │  Simulation Engine  │──►  │   Results & UI   │
│(network spec,    │     │ (event-driven or    │     │ (plots, tables,  │
│ adversary model, │     │  Monte Carlo loops) │     │  export)         │
│  padding policy) │     └─────────────────────┘     └──────────────────┘
└──────────────────┘
        ▲                                     ▲
        │                                     │
        └─────────────── Data Loader ─────────┘
                      (real Tor consensus
                     or synthetic graph)
```

### Core Components

- **`network.py`**: Network topology and node modeling
- **`adversary.py`**: Different attacker capability models  
- **`circuit.py`**: Tor circuit construction and analysis
- **`simulator.py`**: Monte Carlo and timing-based simulation engines
- **`timing.py`**: Packet-level timing analysis for correlation attacks
- **`visualization.py`**: Interactive plotting and dashboard creation
- **`cli.py`**: Command-line interface for scripting and automation

## Research Applications

This toolkit enables analysis of:

### Attack Vectors
- **Timing correlation attacks** between entry and exit nodes
- **AS-level adversaries** controlling infrastructure
- **State-level surveillance** scenarios (Five Eyes, etc.)
- **Global passive adversary** capabilities and limitations

### Defensive Measures
- **Geographic diversity** requirements and effectiveness
- **Guard node stickiness** policies and tradeoffs
- **Bandwidth-based selection** vulnerabilities
- **Traffic padding** schemes (future work)

### Network Analysis
- **Vulnerability hotspots** by country or AS
- **Circuit failure** patterns and robustness
- **Scaling behavior** as network size changes
- **Real-world consensus** analysis with historical data

## Theoretical Background

The toolkit implements and validates key theoretical results:

### Basic Correlation Attack
For an adversary controlling `m` out of `N` total nodes, the probability of compromising both entry and exit of a random circuit is:

**F = (m/N)²**

### Multi-Circuit Analysis  
For a client building `C` circuits, the probability of at least one compromise is:

**P(compromise) = 1 - (1 - F)^C**

### Guard Node Defense
Tor's guard node stickiness reduces exposure by limiting the number of entry nodes used per client, but creates a tradeoff where compromised guards expose all of a client's circuits.

## Example Results

Typical findings from the simulation:

- **Random adversaries**: Success rate closely matches theoretical (m/N)²
  - Example: 50/1300 nodes → theoretical 0.0015, observed ~0.0011
- **AS-level adversaries**: Can achieve disproportionate success due to hosting concentration
  - Often achieve 0% success when targeting diverse hosting providers
- **Geographic constraints**: Significantly reduce attack success for country-level adversaries  
  - Five Eyes countries (US,GB,CA,AU,NZ): ~7% success with 399/1300 nodes
- **Guard stickiness**: Provides good protection unless guard nodes are compromised
- **Parameter sweeps**: Show realistic scaling from 0.0% to 0.8% as adversary grows from 10→100 nodes

## License

MIT License - see LICENSE file for details.
