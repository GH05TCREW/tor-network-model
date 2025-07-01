"""
Timing analysis module for modeling packet-level correlation attacks.
"""

from dataclasses import dataclass
from typing import List, Tuple, Optional, Dict
import numpy as np
import scipy.signal
import scipy.stats
from collections import namedtuple
import random


@dataclass
class Packet:
    """Represents a network packet with timing information."""
    timestamp: float
    size: int
    direction: str  # 'in' or 'out'
    sequence_number: Optional[int] = None


PacketStream = List[Packet]


@dataclass
class CorrelationResult:
    """Result of timing correlation analysis."""
    correlation_coefficient: float
    p_value: float
    lag: float
    confidence_interval: Tuple[float, float]
    method: str


class TimingAnalyzer:
    """Performs timing analysis for correlation attacks."""
    
    def __init__(self, 
                 sampling_rate: float = 100.0,  # Hz
                 min_correlation_length: float = 5.0):  # seconds
        self.sampling_rate = sampling_rate
        self.min_correlation_length = min_correlation_length
        
    def correlate_streams(self, 
                         stream1: PacketStream,
                         stream2: PacketStream,
                         method: str = "cross_correlation") -> float:
        """Correlate two packet streams using timing analysis."""
        
        if method == "cross_correlation":
            return self._cross_correlation(stream1, stream2)
        elif method == "mutual_information":
            return self._mutual_information(stream1, stream2)
        elif method == "dtw":
            return self._dynamic_time_warping(stream1, stream2)
        else:
            raise ValueError(f"Unknown correlation method: {method}")
    
    def _cross_correlation(self, 
                          stream1: PacketStream, 
                          stream2: PacketStream) -> float:
        """Perform cross-correlation analysis."""
        # Convert streams to time series
        ts1 = self._stream_to_timeseries(stream1)
        ts2 = self._stream_to_timeseries(stream2)
        
        if len(ts1) == 0 or len(ts2) == 0:
            return 0.0
        
        # Normalize to same length
        min_len = min(len(ts1), len(ts2))
        ts1 = ts1[:min_len]
        ts2 = ts2[:min_len]
        
        # Calculate cross-correlation
        correlation = scipy.signal.correlate(ts1, ts2, mode='valid')
        
        # Normalize
        norm1 = np.sqrt(np.sum(ts1**2))
        norm2 = np.sqrt(np.sum(ts2**2))
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        normalized_corr = correlation / (norm1 * norm2)
        
        # Return maximum correlation
        return float(np.max(np.abs(normalized_corr)))
    
    def _mutual_information(self, 
                           stream1: PacketStream,
                           stream2: PacketStream) -> float:
        """Calculate mutual information between streams."""
        # Convert to time series with binning
        ts1 = self._stream_to_binned_series(stream1, bin_size=0.1)
        ts2 = self._stream_to_binned_series(stream2, bin_size=0.1)
        
        if len(ts1) == 0 or len(ts2) == 0:
            return 0.0
        
        # Align time series
        min_len = min(len(ts1), len(ts2))
        ts1 = ts1[:min_len]
        ts2 = ts2[:min_len]
        
        # Calculate mutual information using scipy
        # First, discretize the continuous values
        bins = 10
        ts1_discrete = np.digitize(ts1, np.linspace(ts1.min(), ts1.max(), bins))
        ts2_discrete = np.digitize(ts2, np.linspace(ts2.min(), ts2.max(), bins))
        
        # Calculate mutual information
        try:
            mi = scipy.stats.contingency.mutual_info(ts1_discrete, ts2_discrete)
            # Normalize by joint entropy
            joint_entropy = scipy.stats.entropy(
                np.histogram2d(ts1_discrete, ts2_discrete, bins=bins)[0].flatten()
            )
            if joint_entropy > 0:
                return mi / joint_entropy
            else:
                return 0.0
        except:
            return 0.0
    
    def _dynamic_time_warping(self,
                             stream1: PacketStream,
                             stream2: PacketStream) -> float:
        """Simple DTW-based correlation."""
        # Convert to time series
        ts1 = self._stream_to_timeseries(stream1)
        ts2 = self._stream_to_timeseries(stream2)
        
        if len(ts1) == 0 or len(ts2) == 0:
            return 0.0
        
        # Simple DTW implementation
        distance = self._dtw_distance(ts1, ts2)
        
        # Convert distance to similarity score
        max_possible_distance = max(len(ts1), len(ts2)) * max(
            np.max(np.abs(ts1)) if len(ts1) > 0 else 1,
            np.max(np.abs(ts2)) if len(ts2) > 0 else 1
        )
        
        if max_possible_distance > 0:
            similarity = 1.0 - (distance / max_possible_distance)
            return max(0.0, similarity)
        else:
            return 0.0
    
    def _dtw_distance(self, ts1: np.ndarray, ts2: np.ndarray) -> float:
        """Calculate DTW distance between two time series."""
        n, m = len(ts1), len(ts2)
        
        # Initialize distance matrix
        dtw_matrix = np.full((n + 1, m + 1), np.inf)
        dtw_matrix[0, 0] = 0
        
        # Fill the matrix
        for i in range(1, n + 1):
            for j in range(1, m + 1):
                cost = abs(ts1[i-1] - ts2[j-1])
                dtw_matrix[i, j] = cost + min(
                    dtw_matrix[i-1, j],      # insertion
                    dtw_matrix[i, j-1],      # deletion
                    dtw_matrix[i-1, j-1]     # match
                )
        
        return dtw_matrix[n, m]
    
    def _stream_to_timeseries(self, stream: PacketStream) -> np.ndarray:
        """Convert packet stream to time series of packet rates."""
        if not stream:
            return np.array([])
        
        # Get time bounds
        start_time = min(p.timestamp for p in stream)
        end_time = max(p.timestamp for p in stream)
        duration = end_time - start_time
        
        if duration <= 0:
            return np.array([0.0])
        
        # Create time bins
        num_bins = int(duration * self.sampling_rate)
        if num_bins <= 0:
            num_bins = 1
        
        bin_size = duration / num_bins
        time_series = np.zeros(num_bins)
        
        # Count packets in each bin
        for packet in stream:
            bin_idx = int((packet.timestamp - start_time) / bin_size)
            if 0 <= bin_idx < num_bins:
                time_series[bin_idx] += packet.size
        
        return time_series
    
    def _stream_to_binned_series(self, 
                                stream: PacketStream, 
                                bin_size: float) -> np.ndarray:
        """Convert stream to binned time series."""
        if not stream:
            return np.array([])
        
        # Get time bounds
        start_time = min(p.timestamp for p in stream)
        end_time = max(p.timestamp for p in stream)
        
        # Create bins
        num_bins = int((end_time - start_time) / bin_size) + 1
        bins = np.zeros(num_bins)
        
        # Fill bins
        for packet in stream:
            bin_idx = int((packet.timestamp - start_time) / bin_size)
            if 0 <= bin_idx < num_bins:
                bins[bin_idx] += packet.size
        
        return bins
    
    def detect_patterns(self, stream: PacketStream) -> Dict[str, float]:
        """Detect timing patterns in a packet stream."""
        if not stream:
            return {}
        
        timestamps = [p.timestamp for p in stream]
        sizes = [p.size for p in stream]
        
        # Calculate inter-arrival times
        inter_arrivals = np.diff(timestamps)
        
        patterns = {
            "mean_inter_arrival": np.mean(inter_arrivals) if len(inter_arrivals) > 0 else 0,
            "std_inter_arrival": np.std(inter_arrivals) if len(inter_arrivals) > 0 else 0,
            "mean_packet_size": np.mean(sizes),
            "std_packet_size": np.std(sizes),
            "total_bytes": sum(sizes),
            "packet_rate": len(stream) / (max(timestamps) - min(timestamps)) if len(timestamps) > 1 else 0,
        }
        
        # Detect periodicity
        if len(inter_arrivals) > 10:
            # Simple autocorrelation for periodicity detection
            autocorr = np.correlate(inter_arrivals, inter_arrivals, mode='full')
            autocorr = autocorr[autocorr.size // 2:]
            autocorr = autocorr / autocorr[0]  # Normalize
            
            # Find peaks
            if len(autocorr) > 5:
                peaks = scipy.signal.find_peaks(autocorr[1:], height=0.3)[0]
                if len(peaks) > 0:
                    patterns["dominant_period"] = float(peaks[0] + 1)  # +1 because we excluded lag 0
                else:
                    patterns["dominant_period"] = 0.0
            else:
                patterns["dominant_period"] = 0.0
        else:
            patterns["dominant_period"] = 0.0
        
        return patterns


# Utility functions for generating synthetic traffic

def generate_packet_stream(duration: float,
                          base_rate: float = 10.0,  # packets per second
                          jitter: float = 0.1,
                          delay: float = 0.0,
                          packet_size_mean: int = 1500,
                          packet_size_std: int = 500,
                          burst_probability: float = 0.1,
                          burst_multiplier: float = 5.0) -> PacketStream:
    """Generate a synthetic packet stream with realistic timing."""
    
    stream = []
    current_time = delay
    packet_id = 0
    
    while current_time < duration + delay:
        # Determine if this is a burst period
        is_burst = random.random() < burst_probability
        rate = base_rate * burst_multiplier if is_burst else base_rate
        
        # Calculate inter-arrival time (exponential distribution)
        inter_arrival = random.expovariate(rate)
        
        # Add jitter
        jitter_amount = random.uniform(-jitter, jitter)
        current_time += inter_arrival + jitter_amount
        
        if current_time >= duration + delay:
            break
        
        # Generate packet size
        size = max(64, int(random.normalvariate(packet_size_mean, packet_size_std)))
        
        # Create packet
        packet = Packet(
            timestamp=current_time,
            size=size,
            direction="out",  # Default direction
            sequence_number=packet_id
        )
        
        stream.append(packet)
        packet_id += 1
    
    return stream


def add_padding_to_stream(stream: PacketStream,
                         padding_rate: float = 1.0,  # padding packets per second
                         padding_size: int = 64) -> PacketStream:
    """Add padding packets to a stream to defeat timing analysis."""
    
    if not stream:
        return stream
    
    padded_stream = stream.copy()
    
    # Get stream time bounds
    start_time = min(p.timestamp for p in stream)
    end_time = max(p.timestamp for p in stream)
    
    # Generate padding packets
    current_time = start_time
    padding_id = 1000000  # High sequence numbers for padding
    
    while current_time < end_time:
        # Exponential inter-arrival for padding
        inter_arrival = random.expovariate(padding_rate)
        current_time += inter_arrival
        
        if current_time >= end_time:
            break
        
        # Create padding packet
        padding_packet = Packet(
            timestamp=current_time,
            size=padding_size,
            direction="out",
            sequence_number=padding_id
        )
        
        padded_stream.append(padding_packet)
        padding_id += 1
    
    # Sort by timestamp
    padded_stream.sort(key=lambda p: p.timestamp)
    
    return padded_stream


def simulate_circuit_latency(stream: PacketStream,
                           base_latency: float = 0.5,  # seconds
                           latency_variance: float = 0.1) -> PacketStream:
    """Simulate circuit latency effects on packet timing."""
    
    delayed_stream = []
    
    for packet in stream:
        # Add random latency
        latency = random.normalvariate(base_latency, latency_variance)
        latency = max(0.001, latency)  # Minimum 1ms latency
        
        delayed_packet = Packet(
            timestamp=packet.timestamp + latency,
            size=packet.size,
            direction=packet.direction,
            sequence_number=packet.sequence_number
        )
        
        delayed_stream.append(delayed_packet)
    
    return delayed_stream
