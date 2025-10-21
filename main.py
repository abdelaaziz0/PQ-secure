
import asyncio
import argparse
import logging
import sys
from pathlib import Path

from src.crypto.engine import CryptoConfig
from src.server.server import PQSyncServer
from src.client.client import PQSyncClient
from src.benchmark.benchmark import Benchmarker

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('pqsync.log')
    ]
)
logger = logging.getLogger(__name__)


def validate_paths(*paths):
    """Validate and create necessary directories"""
    for path in paths:
        Path(path).mkdir(parents=True, exist_ok=True)


async def run_server(args):
    """Run server mode"""
    logger.info("=== Starting PQ-Secure Sync Server v2.0 ===")
    
    # Validate paths
    validate_paths(args.sync_dir, args.keys_dir)
    
    # Create configuration
    config = CryptoConfig(
        kem_algorithm=args.kem,
        sig_algorithm=args.sig,
        key_rotation_interval=args.key_rotation
    )
    
    logger.info(f"Using algorithms: {config.kem_algorithm} + {config.sig_algorithm}")
    
    # Create and run server
    server = PQSyncServer(
        host=args.host,
        port=args.port,
        sync_dir=Path(args.sync_dir),
        keys_dir=Path(args.keys_dir),
        config=config
    )
    
    try:
        await server.run()
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        raise


async def run_client(args):
    """Run client mode"""
    logger.info("=== Starting PQ-Secure Sync Client v2.0 ===")
    
    # Validate paths
    validate_paths(args.sync_dir, args.keys_dir)
    
    # Create configuration
    config = CryptoConfig(
        kem_algorithm=args.kem,
        sig_algorithm=args.sig,
        key_rotation_interval=args.key_rotation
    )
    
    logger.info(f"Connecting to {args.host}:{args.port}")
    logger.info(f"Using algorithms: {config.kem_algorithm} + {config.sig_algorithm}")
    
    # Create and run client
    client = PQSyncClient(
        host=args.host,
        port=args.port,
        sync_dir=Path(args.sync_dir),
        keys_dir=Path(args.keys_dir),
        config=config
    )
    
    try:
        await client.run()
    except KeyboardInterrupt:
        logger.info("Client shutdown requested")
    except Exception as e:
        logger.error(f"Client error: {e}", exc_info=True)
        raise


async def run_benchmark(args):
    """Run benchmark mode"""
    logger.info("=== Starting PQ-Secure Sync Benchmark ===")
    
    # Validate output directory
    validate_paths(args.output)
    
    benchmarker = Benchmarker(
        output_dir=Path(args.output),
        constrained=args.constrained
    )
    
    if args.all:
        logger.info("Testing all algorithm combinations...")
        await benchmarker.test_all_combinations()
    else:
        config = CryptoConfig(
            kem_algorithm=args.kem,
            sig_algorithm=args.sig
        )
        logger.info(f"Testing {config.kem_algorithm} + {config.sig_algorithm}")
        await benchmarker.test_algorithm(config, iterations=args.iterations)
    
    # Save results
    benchmarker.save_results()
    
    # Generate visualizations
    if not args.no_plot:
        benchmarker.generate_report()
    
    # Show recommendations
    if args.all:
        logger.info("\n=== Algorithm Recommendations ===")
        recommendations = benchmarker.compare_algorithms()
        for category, result in recommendations.items():
            logger.info(f"{category}: {result['kem_algorithm']} + {result['sig_algorithm']}")
    
    logger.info("Benchmark completed")


def create_parser():
    """Create argument parser"""
    parser = argparse.ArgumentParser(
        description='PQ-Secure Sync v2.0 - Post-Quantum File Synchronization',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start server
  python main.py server --host 0.0.0.0 --port 8443

  # Start client
  python main.py client --host localhost --port 8443

  # Run benchmarks
  python main.py benchmark --all

  # Constrained benchmark (embedded simulation)
  python main.py benchmark --constrained --kem Kyber768
        """
    )
    
    # Mode selection
    parser.add_argument(
        'mode',
        choices=['server', 'client', 'benchmark'],
        help='Execution mode'
    )
    
    # Common arguments
    parser.add_argument(
        '--host',
        default='localhost',
        help='Server hostname (default: localhost)'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=8443,
        help='Server port (default: 8443)'
    )
    parser.add_argument(
        '--sync-dir',
        default='./sync_data',
        help='Directory to synchronize (default: ./sync_data)'
    )
    parser.add_argument(
        '--keys-dir',
        default='./keys',
        help='Directory for key storage (default: ./keys)'
    )
    
    # Cryptography arguments
    parser.add_argument(
        '--kem',
        default='Kyber768',
        choices=['Kyber768', 'Kyber1024', 'BIKE-L3'],
        help='KEM algorithm (default: Kyber768)'
    )
    parser.add_argument(
        '--sig',
        default='Dilithium3',
        choices=['Dilithium3', 'Dilithium5', 'SPHINCS+-SHA256-128f-robust'],
        help='Signature algorithm (default: Dilithium3)'
    )
    parser.add_argument(
        '--key-rotation',
        type=int,
        default=3600,
        help='Key rotation interval in seconds (default: 3600)'
    )
    
    # Benchmark-specific arguments
    parser.add_argument(
        '--output',
        default='./benchmarks',
        help='Benchmark output directory (default: ./benchmarks)'
    )
    parser.add_argument(
        '--iterations',
        type=int,
        default=10,
        help='Number of benchmark iterations (default: 10)'
    )
    parser.add_argument(
        '--all',
        action='store_true',
        help='Test all algorithm combinations'
    )
    parser.add_argument(
        '--constrained',
        action='store_true',
        help='Simulate constrained/embedded environment'
    )
    parser.add_argument(
        '--no-plot',
        action='store_true',
        help='Skip generating plots'
    )
    
    # Logging
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Minimal output'
    )
    
    return parser


async def main():
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    # Adjust logging level
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.quiet:
        logging.getLogger().setLevel(logging.WARNING)
    
    # Route to appropriate mode
    try:
        if args.mode == 'server':
            await run_server(args)
        elif args.mode == 'client':
            await run_client(args)
        elif args.mode == 'benchmark':
            await run_benchmark(args)
    except KeyboardInterrupt:
        logger.info("\nShutdown requested by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    # Check Python version
    if sys.version_info < (3, 8):
        print("Error: Python 3.8 or higher is required")
        sys.exit(1)
    
    # Run application
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
