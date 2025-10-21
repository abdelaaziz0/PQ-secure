import asyncio
import time
import psutil
import json
from pathlib import Path
from typing import List, Dict
from dataclasses import dataclass, asdict
import logging

from ..crypto.engine import PQCryptoEngine, CryptoConfig, CryptoMetrics
from ..crypto.keystore import KeyStore

logger = logging.getLogger(__name__)


@dataclass
class BenchmarkResult:
    """Single benchmark result"""
    kem_algorithm: str
    sig_algorithm: str
    iterations: int
    avg_handshake_ms: float
    avg_keygen_ms: float
    avg_encaps_ms: float
    avg_decaps_ms: float
    avg_sign_ms: float
    avg_verify_ms: float
    cpu_usage_avg: float
    cpu_usage_max: float
    memory_mb_avg: float
    memory_mb_max: float
    public_key_size: int
    signature_size: int
    ciphertext_size: int
    timestamp: float


class Benchmarker:
    """
    Performance benchmarking for PQ algorithms
    Measures crypto operations, resource usage, and constrained environments
    """
    
    def __init__(self, output_dir: Path, constrained: bool = False):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.constrained = constrained
        self.results: List[BenchmarkResult] = []
        
        # Process for resource monitoring
        self.process = psutil.Process()
    
    async def test_algorithm(self, config: CryptoConfig, 
                            iterations: int = 10) -> BenchmarkResult:
        """
        Benchmark a specific algorithm combination
        Uses CryptoMetrics for measurement separation
        """
        logger.info(f"Benchmarking {config.kem_algorithm} + {config.sig_algorithm}")
        
        # Aggregate metrics
        handshake_times = []
        keygen_times = []
        encaps_times = []
        decaps_times = []
        sign_times = []
        verify_times = []
        cpu_usages = []
        memory_usages = []
        
        key_sizes = None
        
        for i in range(iterations):
            # Create fresh engine and metrics
            engine = PQCryptoEngine(config)
            metrics = CryptoMetrics()
            
            # Monitor resources
            cpu_before = self.process.cpu_percent()
            mem_before = self.process.memory_info().rss / 1024 / 1024
            
            # Test key generation
            keys = metrics.measure_keygen(engine)
            keygen_times.append(metrics.kem_keygen_time_ms + metrics.sig_keygen_time_ms)
            
            if key_sizes is None:
                key_sizes = metrics.key_sizes
            
            # Test encapsulation/decapsulation
            peer_engine = PQCryptoEngine(config)
            peer_engine.generate_keypair()
            
            ciphertext, shared1 = metrics.measure_encapsulation(
                engine, peer_engine.kem_public_key
            )
            encaps_times.append(metrics.kem_encaps_time_ms)
            
            shared2 = metrics.measure_decapsulation(peer_engine, ciphertext)
            decaps_times.append(metrics.kem_decaps_time_ms)
            
            assert shared1 == shared2, "Shared secrets don't match"
            
            # Test signing/verification
            message = b"Benchmark test message"
            
            start = time.perf_counter()
            signature = engine.sign(message)
            sign_times.append((time.perf_counter() - start) * 1000)
            
            start = time.perf_counter()
            is_valid = engine.verify(message, signature, engine.sig_public_key)
            verify_times.append((time.perf_counter() - start) * 1000)
            
            assert is_valid, "Signature verification failed"
            
            # Simulate handshake time
            handshake_time = (
                metrics.kem_keygen_time_ms +
                metrics.sig_keygen_time_ms +
                metrics.kem_encaps_time_ms +
                metrics.kem_decaps_time_ms +
                sign_times[-1] +
                verify_times[-1]
            )
            handshake_times.append(handshake_time)
            
            # Monitor resources
            cpu_after = self.process.cpu_percent()
            mem_after = self.process.memory_info().rss / 1024 / 1024
            
            cpu_usages.append((cpu_before + cpu_after) / 2)
            memory_usages.append(mem_after - mem_before)
            
            # Small delay between iterations
            await asyncio.sleep(0.1)
        
        # Create result
        result = BenchmarkResult(
            kem_algorithm=config.kem_algorithm,
            sig_algorithm=config.sig_algorithm,
            iterations=iterations,
            avg_handshake_ms=sum(handshake_times) / len(handshake_times),
            avg_keygen_ms=sum(keygen_times) / len(keygen_times),
            avg_encaps_ms=sum(encaps_times) / len(encaps_times),
            avg_decaps_ms=sum(decaps_times) / len(decaps_times),
            avg_sign_ms=sum(sign_times) / len(sign_times),
            avg_verify_ms=sum(verify_times) / len(verify_times),
            cpu_usage_avg=sum(cpu_usages) / len(cpu_usages),
            cpu_usage_max=max(cpu_usages),
            memory_mb_avg=sum(memory_usages) / len(memory_usages),
            memory_mb_max=max(memory_usages),
            public_key_size=key_sizes['kem_public'],
            signature_size=len(signature),
            ciphertext_size=len(ciphertext),
            timestamp=time.time()
        )
        
        self.results.append(result)
        return result
    
    async def test_all_combinations(self):
        """Test all supported algorithm combinations"""
        kem_algorithms = ['Kyber768', 'Kyber1024', 'BIKE-L3']
        sig_algorithms = ['Dilithium3', 'Dilithium5', 'SPHINCS+-SHA256-128f-robust']
        
        total = len(kem_algorithms) * len(sig_algorithms)
        count = 0
        
        for kem in kem_algorithms:
            for sig in sig_algorithms:
                count += 1
                logger.info(f"Progress: {count}/{total}")
                
                try:
                    config = CryptoConfig(kem_algorithm=kem, sig_algorithm=sig)
                    await self.test_algorithm(config, iterations=10)
                except Exception as e:
                    logger.error(f"Failed to benchmark {kem}+{sig}: {e}")
        
        logger.info(f"Completed {len(self.results)} benchmarks")
    
    async def test_constrained_environment(self, config: CryptoConfig):
        """
        Test in simulated constrained environment
        Useful for embedded system simulation
        """
        logger.info("Testing in constrained environment simulation")
        
        # Set lower resource limits
        import resource
        
        # Limit memory (soft limit only)
        try:
            soft, hard = resource.getrlimit(resource.RLIMIT_AS)
            if self.constrained:
                # Limit to 256MB for constrained test
                resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, hard))
        except:
            logger.warning("Could not set resource limits")
        
        # Run benchmark with fewer iterations
        result = await self.test_algorithm(config, iterations=5)
        result.kem_algorithm += " (constrained)"
        
        return result
    
    def save_results(self):
        """Save benchmark results to JSON and CSV"""
        timestamp = int(time.time())
        
        # Save JSON
        json_file = self.output_dir / f"benchmark_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(
                [asdict(r) for r in self.results],
                f,
                indent=2
            )
        logger.info(f"Saved results to {json_file}")
        
        # Save CSV
        csv_file = self.output_dir / f"benchmark_{timestamp}.csv"
        with open(csv_file, 'w') as f:
            if self.results:
                # Header
                fields = asdict(self.results[0]).keys()
                f.write(','.join(fields) + '\n')
                
                # Data rows
                for result in self.results:
                    values = [str(v) for v in asdict(result).values()]
                    f.write(','.join(values) + '\n')
        
        logger.info(f"Saved CSV to {csv_file}")
    
    def generate_report(self):
        """Generate performance report with visualizations"""
        if not self.results:
            logger.warning("No results to generate report")
            return
        
        try:
            import matplotlib.pyplot as plt
            import pandas as pd
            
            # Convert to DataFrame
            df = pd.DataFrame([asdict(r) for r in self.results])
            
            # Create comprehensive visualization
            fig, axes = plt.subplots(2, 3, figsize=(18, 12))
            fig.suptitle('PQ-Secure Sync Performance Benchmarks', fontsize=16, fontweight='bold')
            
            # Handshake times
            ax = axes[0, 0]
            df.plot(x='kem_algorithm', y='avg_handshake_ms', kind='bar', ax=ax, legend=False)
            ax.set_title('Average Handshake Time')
            ax.set_ylabel('Time (ms)')
            ax.tick_params(axis='x', rotation=45)
            
            # CPU usage
            ax = axes[0, 1]
            df.plot(x='kem_algorithm', y=['cpu_usage_avg', 'cpu_usage_max'], kind='bar', ax=ax)
            ax.set_title('CPU Usage')
            ax.set_ylabel('Usage (%)')
            ax.tick_params(axis='x', rotation=45)
            
            # Memory usage
            ax = axes[0, 2]
            df.plot(x='kem_algorithm', y=['memory_mb_avg', 'memory_mb_max'], kind='bar', ax=ax)
            ax.set_title('Memory Usage')
            ax.set_ylabel('Memory (MB)')
            ax.tick_params(axis='x', rotation=45)
            
            # Key sizes
            ax = axes[1, 0]
            df.plot(x='kem_algorithm', y='public_key_size', kind='bar', ax=ax, legend=False, color='green')
            ax.set_title('Public Key Size')
            ax.set_ylabel('Size (bytes)')
            ax.tick_params(axis='x', rotation=45)
            
            # Operation breakdown
            ax = axes[1, 1]
            ops = ['avg_encaps_ms', 'avg_decaps_ms', 'avg_sign_ms', 'avg_verify_ms']
            df[ops].plot(kind='bar', ax=ax)
            ax.set_title('Operation Times')
            ax.set_ylabel('Time (ms)')
            ax.set_xlabel('Test Number')
            ax.legend(['Encaps', 'Decaps', 'Sign', 'Verify'])
            
            # Summary statistics table
            ax = axes[1, 2]
            ax.axis('tight')
            ax.axis('off')
            
            summary_data = [
                ['Metric', 'Min', 'Mean', 'Max'],
                ['Handshake (ms)', 
                 f"{df['avg_handshake_ms'].min():.2f}",
                 f"{df['avg_handshake_ms'].mean():.2f}",
                 f"{df['avg_handshake_ms'].max():.2f}"],
                ['CPU (%)',
                 f"{df['cpu_usage_avg'].min():.2f}",
                 f"{df['cpu_usage_avg'].mean():.2f}",
                 f"{df['cpu_usage_max'].max():.2f}"],
                ['Memory (MB)',
                 f"{df['memory_mb_avg'].min():.2f}",
                 f"{df['memory_mb_avg'].mean():.2f}",
                 f"{df['memory_mb_max'].max():.2f}"]
            ]
            
            table = ax.table(cellText=summary_data, cellLoc='center', loc='center')
            table.auto_set_font_size(False)
            table.set_fontsize(10)
            table.scale(1, 2)
            ax.set_title('Summary Statistics', pad=20)
            
            plt.tight_layout()
            
            # Save figure
            timestamp = int(time.time())
            plot_file = self.output_dir / f"benchmark_plot_{timestamp}.png"
            plt.savefig(plot_file, dpi=150, bbox_inches='tight')
            logger.info(f"Saved plot to {plot_file}")
            
            plt.close()
            
        except ImportError:
            logger.warning("matplotlib/pandas not installed, skipping visualization")
    
    def compare_algorithms(self) -> Dict:
        """Compare algorithms and find optimal choices"""
        if not self.results:
            return {}
        
        import pandas as pd
        df = pd.DataFrame([asdict(r) for r in self.results])
        
        recommendations = {
            'fastest_handshake': df.loc[df['avg_handshake_ms'].idxmin()],
            'lowest_cpu': df.loc[df['cpu_usage_avg'].idxmin()],
            'lowest_memory': df.loc[df['memory_mb_avg'].idxmin()],
            'smallest_keys': df.loc[df['public_key_size'].idxmin()]
        }
        
        return {k: v.to_dict() for k, v in recommendations.items()}
