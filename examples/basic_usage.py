#!/usr/bin/env python3
"""
Basic usage example for the Tor Network Model toolkit.

This script demonstrates the fundamental workflow:
1. Generate a synthetic Tor network
2. Create an adversary model
3. Build circuits with realistic constraints
4. Run Monte Carlo simulation
5. Visualize results
"""

import sys
import os
sys.path.append('..')

from tor_sim import (
    Network, RandomAdversary, CircuitBuilder, CircuitConstraints,
    MonteCarloSimulator, SimulationConfig, Visualizer
)

def main():
    print("Tor Network Model - Basic Example")
    print("=" * 40)
    
    # Step 1: Generate a synthetic network
    print("\n1. Generating synthetic Tor network...")
    network = Network.generate_synthetic(
        num_guards=100,
        num_middles=1000,
        num_exits=200,
        seed=42
    )
    print(f"   Created network with {len(network)} nodes")
    print(f"   Guards: {len(network.guard_nodes)}")
    print(f"   Middles: {len(network.middle_nodes)}")
    print(f"   Exits: {len(network.exit_nodes)}")
    
    # Step 2: Create an adversary
    print("\n2. Creating random adversary...")
    adversary = RandomAdversary(num_compromised=50, seed=42)
    compromised = adversary.compromised_nodes(network)
    compromise_ratio = len(compromised) / len(network)
    print(f"   Adversary controls {len(compromised)} nodes ({compromise_ratio:.3f})")
    print(f"   Theoretical F = (m/N)²: {compromise_ratio**2:.4f}")
    
    # Step 3: Create circuit builder
    print("\n3. Setting up circuit builder...")
    constraints = CircuitConstraints(
        require_different_countries=True,
        use_persistent_guards=True,
        num_guard_nodes=3
    )
    builder = CircuitBuilder(constraints=constraints, seed=42)
    
    # Step 4: Run simulation
    print("\n4. Running Monte Carlo simulation...")
    config = SimulationConfig(
        num_circuits=10000,
        num_clients=100,
        circuits_per_client=100,
        verbose=False
    )
    
    simulator = MonteCarloSimulator(
        network=network,
        adversary=adversary,
        circuit_builder=builder,
        config=config
    )
    
    result = simulator.run()
    
    # Step 5: Display results
    print("\n5. Results:")
    print(f"   Total circuits simulated: {result.total_circuits}")
    print(f"   Compromised circuits: {result.compromised_circuits}")
    print(f"   Compromise rate: {result.compromise_rate:.4f}")
    print(f"   Expected (theoretical): {compromise_ratio**2:.4f}")
    print(f"   Simulation time: {result.simulation_time:.2f} seconds")
    
    # Step 6: Basic visualization
    print("\n6. Creating visualization...")
    try:
        visualizer = Visualizer()
        
        # Create a simple bar chart comparing theoretical vs observed
        import plotly.graph_objects as go
        
        fig = go.Figure()
        fig.add_trace(go.Bar(
            x=['Theoretical', 'Observed'],
            y=[compromise_ratio**2, result.compromise_rate],
            marker_color=['lightblue', 'lightcoral']
        ))
        
        fig.update_layout(
            title='Attack Success Rate: Theoretical vs Observed',
            yaxis_title='Compromise Rate',
            height=400
        )
        
        # Save plot
        fig.write_html('basic_example_results.html')
        print("   Visualization saved to 'basic_example_results.html'")
        
    except Exception as e:
        print(f"   Visualization failed: {e}")
    
    print("\nExample completed successfully!")
    print("For more advanced examples, see the Jupyter notebooks in the notebooks/ directory.")

if __name__ == '__main__':
    main()
