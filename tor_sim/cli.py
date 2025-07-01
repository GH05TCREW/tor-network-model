"""
Command-line interface for the Tor network simulation toolkit.
"""

import click
import json
import logging
import os
import sys
from pathlib import Path
from typing import Optional, List

from . import (
    Network, RandomAdversary, ASLevelAdversary, CountryLevelAdversary, 
    GPAAdversary, HybridAdversary, StrategyAdversary,
    CircuitBuilder, CircuitConstraints, PathSelectionPolicy,
    MonteCarloSimulator, TimingSimulator, BatchSimulator,
    SimulationConfig, Visualizer
)


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@click.group()
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.pass_context
def cli(ctx, verbose):
    """Tor Network Model - Research toolkit for timing analysis attacks."""
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose
    
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)


@cli.command()
@click.option('--consensus', type=click.Path(exists=True), 
              help='Path to Tor consensus file')
@click.option('--synthetic', is_flag=True, 
              help='Use synthetic network instead of consensus')
@click.option('--guards', default=100, type=int,
              help='Number of guard nodes (synthetic only)')
@click.option('--middles', default=1000, type=int,
              help='Number of middle nodes (synthetic only)')
@click.option('--exits', default=200, type=int,
              help='Number of exit nodes (synthetic only)')
@click.option('--output', '-o', type=click.Path(), 
              help='Output file for network data')
@click.option('--seed', type=int, help='Random seed for reproducibility')
@click.pass_context
def generate_network(ctx, consensus, synthetic, guards, middles, exits, output, seed):
    """Generate or load a Tor network topology."""
    
    if consensus and synthetic:
        click.echo("Error: Cannot specify both --consensus and --synthetic", err=True)
        sys.exit(1)
    
    if consensus:
        click.echo(f"Loading network from consensus: {consensus}")
        network = Network.from_consensus(consensus)
    else:
        click.echo(f"Generating synthetic network: {guards} guards, {middles} middles, {exits} exits")
        network = Network.generate_synthetic(
            num_guards=guards,
            num_middles=middles, 
            num_exits=exits,
            seed=seed
        )
    
    click.echo(f"Network loaded: {len(network)} total nodes")
    click.echo(f"  Guards: {len(network.guard_nodes)}")
    click.echo(f"  Middles: {len(network.middle_nodes)}")
    click.echo(f"  Exits: {len(network.exit_nodes)}")
    
    if output:
        network.to_json(output)
        click.echo(f"Network saved to: {output}")


@cli.command()
@click.option('--network', '-n', type=click.Path(exists=True), required=True,
              help='Path to network JSON file')
@click.option('--adversary', '-a', 
              type=click.Choice(['random', 'as_level', 'country_level', 'gpa', 'hybrid', 'strategic']),
              default='random', help='Type of adversary')
@click.option('--num-compromised', '-m', type=int, default=50,
              help='Number of nodes to compromise (random adversary)')
@click.option('--countries', type=str,
              help='Comma-separated list of controlled countries')
@click.option('--as-numbers', type=str,
              help='Comma-separated list of controlled AS numbers')
@click.option('--circuits', '-c', type=int, default=10000,
              help='Number of circuits to simulate')
@click.option('--clients', type=int, default=100,
              help='Number of clients')
@click.option('--circuits-per-client', type=int, default=100,
              help='Circuits per client')
@click.option('--timing', is_flag=True,
              help='Enable timing analysis simulation')
@click.option('--output', '-o', type=click.Path(),
              help='Output file for results')
@click.option('--seed', type=int, help='Random seed')
@click.pass_context
def simulate(ctx, network, adversary, num_compromised, countries, as_numbers,
             circuits, clients, circuits_per_client, timing, output, seed):
    """Run a correlation attack simulation."""
    
    # Load network
    click.echo(f"Loading network from: {network}")
    net = Network.from_json(network)
    
    # Create adversary
    click.echo(f"Creating {adversary} adversary")
    if adversary == 'random':
        adv = RandomAdversary(num_compromised, seed=seed)
    elif adversary == 'as_level':
        if not as_numbers:
            click.echo("Error: --as-numbers required for AS-level adversary", err=True)
            sys.exit(1)
        as_list = [int(x.strip()) for x in as_numbers.split(',')]
        adv = ASLevelAdversary(as_list)
    elif adversary == 'country_level':
        if not countries:
            click.echo("Error: --countries required for country-level adversary", err=True)
            sys.exit(1)
        country_list = [x.strip() for x in countries.split(',')]
        adv = CountryLevelAdversary(country_list)
    elif adversary == 'gpa':
        ratio = num_compromised / len(net) if len(net) > 0 else 0.1
        adv = GPAAdversary(ratio)
    elif adversary == 'hybrid':
        country_list = [x.strip() for x in countries.split(',')] if countries else []
        as_list = [int(x.strip()) for x in as_numbers.split(',')] if as_numbers else []
        adv = HybridAdversary(
            random_nodes=num_compromised,
            controlled_countries=country_list,
            controlled_as_numbers=as_list
        )
    elif adversary == 'strategic':
        adv = StrategyAdversary(num_nodes=num_compromised)
    
    # Create circuit builder
    constraints = CircuitConstraints()
    builder = CircuitBuilder(constraints=constraints, seed=seed)
    
    # Create simulation config
    config = SimulationConfig(
        num_circuits=circuits,
        num_clients=clients,
        circuits_per_client=circuits_per_client,
        enable_timing_analysis=timing,
        network_seed=seed,
        adversary_seed=seed,
        circuit_seed=seed,
        verbose=ctx.obj['verbose']
    )
    
    # Run simulation
    if timing:
        click.echo("Running timing-based simulation...")
        simulator = TimingSimulator(net, adv, builder, config)
    else:
        click.echo("Running Monte Carlo simulation...")
        simulator = MonteCarloSimulator(net, adv, builder, config)
    
    result = simulator.run()
    
    # Display results
    click.echo("\n=== Simulation Results ===")
    click.echo(f"Total circuits: {result.total_circuits}")
    click.echo(f"Compromised circuits: {result.compromised_circuits}")
    click.echo(f"Compromise rate: {result.compromise_rate:.4f}")
    click.echo(f"Guard compromise rate: {result.guard_compromise_rate:.4f}")
    click.echo(f"Exit compromise rate: {result.exit_compromise_rate:.4f}")
    click.echo(f"Both ends compromised: {result.both_compromise_rate:.4f}")
    click.echo(f"Simulation time: {result.simulation_time:.2f} seconds")
    
    if timing and result.timing_correlation_rate > 0:
        click.echo(f"Timing correlation rate: {result.timing_correlation_rate:.4f}")
        click.echo(f"False positive rate: {result.false_positive_rate:.4f}")
    
    # Save results
    if output:
        result_dict = {
            "total_circuits": result.total_circuits,
            "compromised_circuits": result.compromised_circuits,
            "compromise_rate": result.compromise_rate,
            "guard_compromise_rate": result.guard_compromise_rate,
            "exit_compromise_rate": result.exit_compromise_rate,
            "both_compromise_rate": result.both_compromise_rate,
            "network_size": result.network_size,
            "adversary_node_count": result.adversary_node_count,
            "adversary_compromise_ratio": result.adversary_compromise_ratio,
            "simulation_time": result.simulation_time,
            "success_by_num_circuits": result.success_by_num_circuits,
        }
        
        if timing:
            result_dict.update({
                "timing_correlation_rate": result.timing_correlation_rate,
                "false_positive_rate": result.false_positive_rate,
            })
        
        with open(output, 'w') as f:
            json.dump(result_dict, f, indent=2)
        
        click.echo(f"Results saved to: {output}")


@cli.command()
@click.option('--network', '-n', type=click.Path(exists=True), required=True,
              help='Path to network JSON file')
@click.option('--adversary', '-a',
              type=click.Choice(['random', 'as_level', 'country_level', 'gpa']),
              default='random', help='Type of adversary')
@click.option('--parameter', '-p', default='num_compromised',
              help='Parameter to sweep')
@click.option('--min-value', type=int, default=10,
              help='Minimum parameter value')
@click.option('--max-value', type=int, default=100,
              help='Maximum parameter value')
@click.option('--steps', type=int, default=10,
              help='Number of steps in sweep')
@click.option('--circuits', '-c', type=int, default=10000,
              help='Number of circuits per simulation')
@click.option('--output', '-o', type=click.Path(),
              help='Output file for results')
@click.option('--plot', is_flag=True,
              help='Generate plots')
@click.pass_context
def sweep(ctx, network, adversary, parameter, min_value, max_value, steps,
          circuits, output, plot):
    """Run parameter sweep analysis."""
    
    # Load network
    net = Network.from_json(network)
    
    # Create circuit builder
    builder = CircuitBuilder()
    
    # Create batch simulator
    config = SimulationConfig(
        num_circuits=circuits,
        verbose=ctx.obj['verbose']
    )
    batch_sim = BatchSimulator(config)
    
    # Define parameter values
    param_values = list(range(min_value, max_value + 1, (max_value - min_value) // steps))
    
    # Define adversary factory
    if adversary == 'random':
        def adversary_factory(**kwargs):
            return RandomAdversary(**kwargs)
    elif adversary == 'gpa':
        def adversary_factory(**kwargs):
            if 'num_compromised' in kwargs:
                ratio = kwargs['num_compromised'] / len(net)
                return GPAAdversary(ratio)
            return GPAAdversary(**kwargs)
    else:
        click.echo(f"Parameter sweep not supported for {adversary} adversary", err=True)
        sys.exit(1)
    
    # Run sweep
    click.echo(f"Running parameter sweep: {parameter} from {min_value} to {max_value}")
    results = batch_sim.run_parameter_sweep(
        net, adversary_factory, builder, parameter, param_values
    )
    
    # Display summary
    click.echo(f"\nSweep completed. Results for {len(results)} simulations:")
    for result in results:
        param_val = getattr(result, 'parameter_value', 'unknown')
        click.echo(f"  {parameter}={param_val}: compromise_rate={result.compromise_rate:.4f}")
    
    # Save results
    if output:
        results_data = []
        for result in results:
            results_data.append({
                "parameter_value": getattr(result, 'parameter_value', None),
                "total_circuits": result.total_circuits,
                "compromised_circuits": result.compromised_circuits,
                "compromise_rate": result.compromise_rate,
                "simulation_time": result.simulation_time,
            })
        
        with open(output, 'w') as f:
            json.dump(results_data, f, indent=2)
        
        click.echo(f"Results saved to: {output}")
    
    # Generate plots
    if plot:
        visualizer = Visualizer()
        fig = visualizer.plot_compromise_rate_vs_adversary_size(results, parameter)
        
        plot_file = output.replace('.json', '.html') if output else 'sweep_results.html'
        fig.write_html(plot_file)
        click.echo(f"Plot saved to: {plot_file}")


@cli.command()
@click.option('--results', '-r', type=click.Path(exists=True), required=True,
              help='Path to simulation results JSON file')
@click.option('--network', '-n', type=click.Path(exists=True),
              help='Path to network JSON file (for network plots)')
@click.option('--output-dir', '-o', type=click.Path(), default='plots',
              help='Output directory for plots')
@click.option('--format', 'formats', multiple=True, default=['html'],
              type=click.Choice(['html', 'png', 'pdf']),
              help='Output formats')
def visualize(results, network, output_dir, formats):
    """Generate visualizations from simulation results."""
    from . import Visualizer, SimulationResult
    
    # Load results
    with open(results, 'r') as f:
        results_data = json.load(f)
    
    # Convert to SimulationResult objects if needed
    if isinstance(results_data, list):
        # Multiple results (sweep)
        click.echo(f"Loading {len(results_data)} simulation results")
        # For now, just take the first result for single-result visualizations
        result_dict = results_data[0] if results_data else {}
    else:
        # Single result
        result_dict = results_data
    
    visualizer = Visualizer()
    figures = {}
    
    # Handle sweep results (multiple simulations)
    if isinstance(results_data, list) and len(results_data) > 1:
        # Create SimulationResult objects from the sweep data
        sweep_results = []
        for item in results_data:
            result = SimulationResult()
            result.compromise_rate = item.get('compromise_rate', 0)
            result.adversary_node_count = item.get('adversary_node_count', 0)
            result.network_size = item.get('network_size', 1000)  # default
            result.total_circuits = item.get('total_circuits', 0)
            result.simulation_time = item.get('simulation_time', 0)
            result.guard_compromise_rate = item.get('guard_compromise_rate', 0)
            result.exit_compromise_rate = item.get('exit_compromise_rate', 0)
            sweep_results.append(result)
        
        # Generate parameter sweep plot
        parameter_name = "num_compromised"  # Default assumption for sweep
        figures['parameter_sweep'] = visualizer.plot_compromise_rate_vs_adversary_size(
            sweep_results, parameter_name
        )
        click.echo("Generated: Parameter sweep plot")
    
    # Generate plots based on available data
    if 'success_by_num_circuits' in result_dict and result_dict['success_by_num_circuits']:
        result = SimulationResult()
        result.success_by_num_circuits = result_dict['success_by_num_circuits']
        result.compromise_rate = result_dict.get('compromise_rate', 0)
        
        figures['success_by_circuits'] = visualizer.plot_success_by_circuit_count(result)
        click.echo("Generated: Success by circuit count plot")
    
    # Network visualizations (if network file provided)
    if network:
        net = Network.from_json(network)
        
        figures['geographic_distribution'] = visualizer.plot_network_geography(net)
        figures['bandwidth_distribution'] = visualizer.plot_bandwidth_distribution(net)
        click.echo("Generated: Network analysis plots")
    
    # Save plots
    if figures:
        from .visualization import save_plots
        save_plots(figures, output_dir, list(formats))
        click.echo(f"Plots saved to: {output_dir}")
    else:
        click.echo("No plots generated - insufficient data")


def main():
    """Main entry point for the CLI."""
    cli()


if __name__ == '__main__':
    main()
