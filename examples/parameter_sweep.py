#!/usr/bin/env python3
"""
Parameter sweep analysis example.

This script demonstrates how to analyze attack success rates
across different adversary strengths and network configurations.
"""

import sys
import os
sys.path.append('..')

import numpy as np
import plotly.graph_objects as go
from plotly.subplots import make_subplots

from tor_sim import (
    Network, RandomAdversary, ASLevelAdversary, CountryLevelAdversary,
    CircuitBuilder, MonteCarloSimulator, SimulationConfig, Visualizer
)

def parameter_sweep_example():
    """Run parameter sweep analysis comparing different adversary types."""
    
    print("Tor Network Model - Parameter Sweep Example")
    print("=" * 50)
    
    # Create network
    print("Creating synthetic network...")
    network = Network.generate_synthetic(
        num_guards=200,
        num_middles=2000,
        num_exits=400,
        seed=42
    )
    
    # Create circuit builder
    builder = CircuitBuilder(seed=42)
    config = SimulationConfig(
        num_circuits=20000,
        num_clients=200,
        circuits_per_client=100,
        verbose=False
    )
    
    # Parameter sweep: varying number of compromised nodes
    compromise_counts = range(25, 151, 25)  # 25, 50, 75, 100, 125, 150
    
    results = {
        'Random': [],
        'AS-Level': [],
        'Country-Level': []
    }
    
    print(f"\nRunning parameter sweep...")
    print(f"Testing compromise counts: {list(compromise_counts)}")
    
    for m in compromise_counts:
        print(f"\nTesting m={m} compromised nodes:")
        
        # Random adversary
        print("  - Random adversary...")
        random_adv = RandomAdversary(num_compromised=m, seed=42)
        sim = MonteCarloSimulator(network, random_adv, builder, config)
        result = sim.run()
        result.parameter_value = m
        results['Random'].append(result)
        print(f"    Compromise rate: {result.compromise_rate:.4f}")
        
        # AS-level adversary (simulate controlling major hosting providers)
        print("  - AS-level adversary...")
        # Use number of AS proportional to m
        num_as = max(1, m // 50)  # 1 AS per 50 nodes
        major_as = [16509, 13335, 20940, 15169, 8075]  # Major cloud providers
        as_adv = ASLevelAdversary(controlled_as_numbers=major_as[:num_as])
        sim = MonteCarloSimulator(network, as_adv, builder, config)
        result = sim.run()
        result.parameter_value = m
        results['AS-Level'].append(result)
        print(f"    Compromise rate: {result.compromise_rate:.4f}")
        
        # Country-level adversary
        print("  - Country-level adversary...")
        # Use number of countries proportional to m
        num_countries = max(1, min(5, m // 30))  # 1 country per 30 nodes, max 5
        countries = ["US", "GB", "CA", "AU", "NZ"]  # Five Eyes
        country_adv = CountryLevelAdversary(controlled_countries=countries[:num_countries])
        sim = MonteCarloSimulator(network, country_adv, builder, config)
        result = sim.run()
        result.parameter_value = m
        results['Country-Level'].append(result)
        print(f"    Compromise rate: {result.compromise_rate:.4f}")
    
    # Create visualization
    print(f"\nCreating visualizations...")
    
    fig = make_subplots(
        rows=2, cols=2,
        subplot_titles=[
            'Attack Success Rate vs Adversary Size',
            'Theoretical vs Observed (Random)',
            'Adversary Effectiveness Comparison',
            'Network Statistics'
        ]
    )
    
    # Plot 1: Success rate vs adversary size
    for adv_type, adv_results in results.items():
        x_vals = [r.parameter_value for r in adv_results]
        y_vals = [r.compromise_rate for r in adv_results]
        
        fig.add_trace(
            go.Scatter(x=x_vals, y=y_vals, mode='lines+markers', name=adv_type),
            row=1, col=1
        )
    
    # Add theoretical line for random adversary
    x_theoretical = list(compromise_counts)
    y_theoretical = [(m / len(network))**2 for m in x_theoretical]
    fig.add_trace(
        go.Scatter(x=x_theoretical, y=y_theoretical, mode='lines', 
                  name='Theoretical (m/N)²', line=dict(dash='dash')),
        row=1, col=1
    )
    
    # Plot 2: Theoretical vs observed for random adversary
    random_results = results['Random']
    theoretical_vals = []
    observed_vals = []
    
    for r in random_results:
        if r.network_size > 0:  # Safe division
            theoretical_vals.append((r.adversary_node_count / r.network_size)**2)
            observed_vals.append(r.compromise_rate)
        else:
            print(f"Warning: Network size is 0, skipping data point")
    
    if theoretical_vals:  # Only add if we have valid data
        fig.add_trace(
            go.Scatter(x=theoretical_vals, y=observed_vals, mode='markers',
                      name='Random Adversary', showlegend=False),
            row=1, col=2
        )
        
        # Add y=x line
        max_val = max(max(theoretical_vals), max(observed_vals))
        fig.add_trace(
            go.Scatter(x=[0, max_val], y=[0, max_val], mode='lines',
                      name='Perfect Match', line=dict(dash='dash'), showlegend=False),
            row=1, col=2
        )
    
    # Plot 3: Final effectiveness comparison
    final_results = {adv_type: adv_results[-1] for adv_type, adv_results in results.items()}
    adv_names = list(final_results.keys())
    compromise_rates = [result.compromise_rate for result in final_results.values()]
    
    fig.add_trace(
        go.Bar(x=adv_names, y=compromise_rates, showlegend=False),
        row=2, col=1
    )
    
    # Plot 4: Network statistics
    country_dist = network.get_country_distribution()
    top_countries = sorted(country_dist.items(), key=lambda x: x[1], reverse=True)[:5]
    countries, counts = zip(*top_countries)
    
    fig.add_trace(
        go.Bar(x=countries, y=counts, showlegend=False),
        row=2, col=2
    )
    
    # Update layout
    fig.update_layout(height=800, title_text="Tor Network Parameter Sweep Analysis")
    fig.update_xaxes(title_text="Number of Compromised Nodes", row=1, col=1)
    fig.update_yaxes(title_text="Compromise Rate", row=1, col=1)
    fig.update_xaxes(title_text="Theoretical Rate", row=1, col=2)
    fig.update_yaxes(title_text="Observed Rate", row=1, col=2)
    fig.update_xaxes(title_text="Adversary Type", row=2, col=1)
    fig.update_yaxes(title_text="Compromise Rate", row=2, col=1)
    fig.update_xaxes(title_text="Country", row=2, col=2)
    fig.update_yaxes(title_text="Node Count", row=2, col=2)
    
    # Save results
    fig.write_html('parameter_sweep_results.html')
    print("Visualization saved to 'parameter_sweep_results.html'")
    
    # Print summary
    print(f"\nSummary Results:")
    print("=" * 40)
    print(f"{'Adversary':<15} {'Nodes':<8} {'Rate':<10} {'Effectiveness'}")
    print("-" * 40)
    
    for adv_type, result in final_results.items():
        # Safe division to avoid ZeroDivisionError
        theoretical_rate = (result.adversary_node_count / result.network_size)**2
        if theoretical_rate > 0:
            effectiveness = result.compromise_rate / theoretical_rate
        else:
            effectiveness = float('inf') if result.compromise_rate > 0 else 0.0
        
        print(f"{adv_type:<15} {result.adversary_node_count:<8} {result.compromise_rate:<10.4f} {effectiveness:<10.2f}x")
    
    print(f"\nEffectiveness shows how much better each adversary performs")
    print(f"compared to the theoretical random baseline.")

if __name__ == '__main__':
    parameter_sweep_example()
