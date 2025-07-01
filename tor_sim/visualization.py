"""
Visualization tools for Tor network analysis and attack simulation results.
"""

import matplotlib.pyplot as plt
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import pandas as pd
import numpy as np
import networkx as nx
from typing import List, Dict, Optional, Tuple, Any
from collections import defaultdict

# Optional seaborn import
try:
    import seaborn as sns
    HAS_SEABORN = True
except ImportError:
    HAS_SEABORN = False

from .network import Network, Node
from .simulator import SimulationResult
from .circuit import Circuit


class Visualizer:
    """Main visualization class for Tor network analysis."""
    
    def __init__(self, style: str = "plotly", theme: str = "plotly_white"):
        self.style = style
        self.theme = theme
        
        # Configure matplotlib if needed
        if style == "matplotlib":
            plt.style.use('seaborn-v0_8' if 'seaborn-v0_8' in plt.style.available else 'default')
            if HAS_SEABORN:
                sns.set_palette("husl")
    
    def plot_compromise_rate_vs_adversary_size(self,
                                              results: List[SimulationResult],
                                              parameter_name: str = "num_compromised") -> go.Figure:
        """Plot attack success rate vs adversary size."""
        
        # Extract data
        x_values = []
        y_values = []
        error_bars = []
        
        for result in results:
            if hasattr(result, 'parameter_value'):
                x_values.append(result.parameter_value)
                y_values.append(result.compromise_rate)
            else:
                x_values.append(result.adversary_node_count)
                y_values.append(result.compromise_rate)
        
        # Create plot
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=x_values,
            y=y_values,
            mode='lines+markers',
            name='Observed Rate',
            line=dict(width=3),
            marker=dict(size=8)
        ))
        
        # Add theoretical line if applicable
        if parameter_name == "num_compromised" and len(results) > 0:
            network_size = float(results[0].network_size)
            theoretical_x = np.array(x_values, dtype=float)
            
            # Safe division
            if network_size > 0:
                theoretical_y = np.power(theoretical_x / network_size, 2)
            else:
                theoretical_y = np.zeros_like(theoretical_x)
            
            fig.add_trace(go.Scatter(
                x=theoretical_x,
                y=theoretical_y,
                mode='lines',
                name='Theoretical (m/N)²',
                line=dict(dash='dash', width=2)
            ))
        
        fig.update_layout(
            title="Attack Success Rate vs Adversary Size",
            xaxis_title=f"Number of Compromised Nodes ({parameter_name})",
            yaxis_title="Circuit Compromise Rate",
            template=self.theme,
            hovermode='x unified'
        )
        
        return fig
    
    def plot_success_by_circuit_count(self,
                                     result: SimulationResult) -> go.Figure:
        """Plot cumulative attack success probability by number of circuits."""
        
        if not result.success_by_num_circuits:
            return go.Figure().add_annotation(
                text="No multi-circuit data available",
                xref="paper", yref="paper",
                x=0.5, y=0.5, showarrow=False
            )
        
        circuits = list(result.success_by_num_circuits.keys())
        success_rates = list(result.success_by_num_circuits.values())
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=circuits,
            y=success_rates,
            mode='lines+markers',
            name='Observed',
            line=dict(width=3),
            marker=dict(size=6)
        ))
        
        # Add theoretical curve: 1 - (1 - F)^C
        if result.compromise_rate > 0:
            F = float(result.compromise_rate)
            theoretical_x = np.array(circuits, dtype=float)
            
            # Ensure F is in valid range (0, 1)
            F = max(1e-10, min(0.9999, F))
            
            theoretical_y = 1 - np.power(1 - F, theoretical_x)
            
            fig.add_trace(go.Scatter(
                x=theoretical_x,
                y=theoretical_y,
                mode='lines',
                name=f'Theoretical 1-(1-{F:.3f})^C',
                line=dict(dash='dash', width=2)
            ))
        
        fig.update_layout(
            title="Cumulative Attack Success Probability",
            xaxis_title="Number of Circuits Built",
            yaxis_title="Probability of At Least One Successful Attack",
            template=self.theme,
            hovermode='x unified'
        )
        
        return fig
    
    def plot_network_geography(self,
                              network: Network,
                              compromised_nodes: Optional[List[str]] = None) -> go.Figure:
        """Plot geographic distribution of nodes."""
        
        # Get country distribution
        country_counts = network.get_country_distribution()
        
        # Separate compromised vs safe nodes
        if compromised_nodes:
            compromised_set = set(compromised_nodes)
            safe_counts = defaultdict(int)
            comp_counts = defaultdict(int)
            
            for node in network.nodes.values():
                country = node.country_code or "Unknown"
                if node.fingerprint in compromised_set:
                    comp_counts[country] += 1
                else:
                    safe_counts[country] += 1
            
            countries = list(set(safe_counts.keys()) | set(comp_counts.keys()))
            safe_values = [safe_counts[c] for c in countries]
            comp_values = [comp_counts[c] for c in countries]
            
            fig = go.Figure()
            
            fig.add_trace(go.Bar(
                x=countries,
                y=safe_values,
                name='Safe Nodes',
                marker_color='lightblue'
            ))
            
            fig.add_trace(go.Bar(
                x=countries,
                y=comp_values,
                name='Compromised Nodes',
                marker_color='red'
            ))
            
            fig.update_layout(barmode='stack')
        
        else:
            countries = list(country_counts.keys())
            counts = list(country_counts.values())
            
            fig = go.Figure()
            
            fig.add_trace(go.Bar(
                x=countries,
                y=counts,
                name='Total Nodes',
                marker_color='lightblue'
            ))
        
        fig.update_layout(
            title="Geographic Distribution of Tor Nodes",
            xaxis_title="Country",
            yaxis_title="Number of Nodes",
            template=self.theme
        )
        
        return fig
    
    def plot_bandwidth_distribution(self,
                                   network: Network,
                                   node_type: str = "all") -> go.Figure:
        """Plot bandwidth distribution of nodes."""
        
        if node_type == "guard":
            nodes = network.guard_nodes
        elif node_type == "exit":
            nodes = network.exit_nodes
        elif node_type == "middle":
            nodes = network.middle_nodes
        else:
            nodes = list(network.nodes.values())
        
        bandwidths = [node.effective_bandwidth for node in nodes]
        
        fig = go.Figure()
        
        fig.add_trace(go.Histogram(
            x=bandwidths,
            nbinsx=50,
            name=f'{node_type.title()} Nodes',
            opacity=0.7
        ))
        
        fig.update_layout(
            title=f"Bandwidth Distribution - {node_type.title()} Nodes",
            xaxis_title="Effective Bandwidth (KB/s)",
            yaxis_title="Number of Nodes",
            template=self.theme
        )
        
        return fig
    
    def plot_network_graph(self,
                          network: Network,
                          sample_circuits: List[Circuit],
                          compromised_nodes: Optional[List[str]] = None,
                          max_nodes: int = 100) -> go.Figure:
        """Plot network graph with sample circuits highlighted."""
        
        # Sample nodes if network is too large
        if len(network.nodes) > max_nodes:
            sampled_nodes = list(network.nodes.values())[:max_nodes]
        else:
            sampled_nodes = list(network.nodes.values())
        
        # Create graph
        G = nx.Graph()
        
        # Add nodes
        node_colors = []
        node_sizes = []
        node_text = []
        
        compromised_set = set(compromised_nodes) if compromised_nodes else set()
        
        for node in sampled_nodes:
            G.add_node(node.fingerprint)
            
            # Color by type and compromise status
            if node.fingerprint in compromised_set:
                color = 'red'
            elif node.is_guard:
                color = 'green'
            elif node.is_exit:
                color = 'blue'
            else:
                color = 'gray'
            
            node_colors.append(color)
            node_sizes.append(max(10, node.effective_bandwidth / 100))
            node_text.append(f"{node.nickname}<br>BW: {node.effective_bandwidth}")
        
        # Add circuit edges
        for circuit in sample_circuits[:10]:  # Limit to first 10 circuits
            if (circuit.guard.fingerprint in G.nodes and 
                circuit.middle.fingerprint in G.nodes and
                circuit.exit.fingerprint in G.nodes):
                
                G.add_edge(circuit.guard.fingerprint, circuit.middle.fingerprint)
                G.add_edge(circuit.middle.fingerprint, circuit.exit.fingerprint)
        
        # Position nodes
        pos = nx.spring_layout(G, k=1, iterations=50)
        
        # Create edge traces
        edge_x = []
        edge_y = []
        
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
        
        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=1, color='lightgray'),
            hoverinfo='none',
            mode='lines'
        )
        
        # Create node trace
        node_x = [pos[node][0] for node in G.nodes()]
        node_y = [pos[node][1] for node in G.nodes()]
        
        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers',
            hoverinfo='text',
            text=node_text,
            marker=dict(
                size=node_sizes,
                color=node_colors,
                line=dict(width=2, color='white')
            )
        )
        
        fig = go.Figure(data=[edge_trace, node_trace])
        
        fig.update_layout(
            title="Tor Network Graph with Sample Circuits",
            titlefont_size=16,
            showlegend=False,
            hovermode='closest',
            margin=dict(b=20,l=5,r=5,t=40),
            annotations=[
                dict(
                    text="Green: Guards, Blue: Exits, Gray: Middles, Red: Compromised",
                    showarrow=False,
                    xref="paper", yref="paper",
                    x=0.005, y=-0.002,
                    xanchor='left', yanchor='bottom',
                    font=dict(size=12)
                )
            ],
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            template=self.theme
        )
        
        return fig
    
    def plot_timing_correlation(self,
                               correlations: List[float],
                               threshold: float = 0.8) -> go.Figure:
        """Plot timing correlation results."""
        
        fig = go.Figure()
        
        # Histogram of correlations
        fig.add_trace(go.Histogram(
            x=correlations,
            nbinsx=50,
            name='Correlations',
            opacity=0.7
        ))
        
        # Add threshold line
        fig.add_vline(
            x=threshold,
            line_dash="dash",
            line_color="red",
            annotation_text=f"Threshold: {threshold}"
        )
        
        # Count above threshold
        above_threshold = sum(1 for c in correlations if c > threshold)
        detection_rate = above_threshold / len(correlations) if correlations else 0
        
        fig.update_layout(
            title=f"Timing Correlation Analysis (Detection Rate: {detection_rate:.2%})",
            xaxis_title="Correlation Coefficient",
            yaxis_title="Frequency",
            template=self.theme
        )
        
        return fig
    
    def create_dashboard(self,
                        results: List[SimulationResult],
                        network: Network,
                        sample_circuits: List[Circuit]) -> go.Figure:
        """Create a comprehensive dashboard."""
        
        # Create subplots
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=[
                "Compromise Rate vs Adversary Size",
                "Geographic Distribution", 
                "Success vs Circuit Count",
                "Bandwidth Distribution"
            ],
            specs=[
                [{"secondary_y": False}, {"secondary_y": False}],
                [{"secondary_y": False}, {"secondary_y": False}]
            ]
        )
        
        # Plot 1: Compromise rate vs adversary size
        if len(results) > 1:
            x_vals = [r.adversary_node_count for r in results]
            y_vals = [r.compromise_rate for r in results]
            
            fig.add_trace(
                go.Scatter(x=x_vals, y=y_vals, mode='lines+markers', name='Compromise Rate'),
                row=1, col=1
            )
        
        # Plot 2: Geographic distribution
        country_dist = network.get_country_distribution()
        countries = list(country_dist.keys())[:10]  # Top 10
        counts = [country_dist[c] for c in countries]
        
        fig.add_trace(
            go.Bar(x=countries, y=counts, name='Nodes by Country'),
            row=1, col=2
        )
        
        # Plot 3: Success vs circuit count
        if results and results[0].success_by_num_circuits:
            result = results[0]
            circuits = list(result.success_by_num_circuits.keys())
            success = list(result.success_by_num_circuits.values())
            
            fig.add_trace(
                go.Scatter(x=circuits, y=success, mode='lines+markers', name='Success Rate'),
                row=2, col=1
            )
        
        # Plot 4: Bandwidth distribution
        bandwidths = [node.effective_bandwidth for node in network.nodes.values()]
        
        fig.add_trace(
            go.Histogram(x=bandwidths, nbinsx=30, name='Bandwidth Dist'),
            row=2, col=2
        )
        
        fig.update_layout(
            height=800,
            showlegend=False,
            title_text="Tor Network Analysis Dashboard",
            template=self.theme
        )
        
        return fig


# Utility functions

def save_plots(figures: Dict[str, go.Figure], 
               output_dir: str = "plots",
               formats: List[str] = ["html", "png"]) -> None:
    """Save multiple plots to files."""
    import os
    
    os.makedirs(output_dir, exist_ok=True)
    
    for name, fig in figures.items():
        for fmt in formats:
            filepath = os.path.join(output_dir, f"{name}.{fmt}")
            
            if fmt == "html":
                fig.write_html(filepath)
            elif fmt == "png":
                fig.write_image(filepath, width=1200, height=800)
            elif fmt == "pdf":
                fig.write_image(filepath, width=1200, height=800)


def export_data_for_plotting(results: List[SimulationResult],
                            filename: str = "simulation_results.csv") -> None:
    """Export simulation results to CSV for external plotting."""
    
    data = []
    for i, result in enumerate(results):
        row = {
            "simulation_id": i,
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
        }
        
        if hasattr(result, 'parameter_value'):
            row["parameter_value"] = result.parameter_value
        
        data.append(row)
    
    df = pd.DataFrame(data)
    df.to_csv(filename, index=False)
    print(f"Results exported to {filename}")
