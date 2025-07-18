#!/usr/bin/env python3
"""
PyWAF - Python Web Application Firewall
Main entry point for the WAF application
"""

import os
import argparse
import sys
from src.core.engine import WAFEngine
from src.core.config import ConfigManager
from src.utils.logger import setup_logging

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Python Web Application Firewall')
    parser.add_argument('-c', '--config', default='config/waf.conf',
                        help='Path to configuration file')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='Enable debug mode')
    return parser.parse_args()

def main():
    """Main entry point for the WAF."""
    args = parse_arguments()
    
    # Setup logging
    log_level = 'DEBUG' if args.debug else 'INFO'
    setup_logging(log_level)
    
    # Load configuration
    config_manager = ConfigManager(args.config)
    config = config_manager.load_config()
    
    try:
        # Initialize and start the WAF engine
        engine = WAFEngine(config)
        engine.start()
    except KeyboardInterrupt:
        print("\nShutting down WAF...")
        sys.exit(0)
    except Exception as e:
        print(f"Error starting WAF: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()