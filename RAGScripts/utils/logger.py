import os
import logging
from datetime import datetime
from typing import Optional

def setup_logger(name: str, verbosity: Optional[int] = 1) -> logging.Logger:
    """Setup and return a logger instance"""
    logger = logging.getLogger(name)
    
    if not logger.handlers:  # Only add handler if none exists
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        # Set log level based on verbosity
        if verbosity == 0:
            logger.setLevel(logging.WARNING)
        elif verbosity == 1:
            logger.setLevel(logging.INFO)
        else:
            logger.setLevel(logging.DEBUG)
    
    return logger

def get_logger(name: str) -> logging.Logger:
    """Get or create a logger instance"""
    return logging.getLogger(name)

def setup_scanner_logger(scanner_name: str, verbosity: int = 0) -> logging.Logger:
    """Setup a dedicated logger for each scanner with verbosity support"""
    return setup_logger(f"scanner.{scanner_name}.{datetime.now().strftime('%Y%m%d')}", verbosity)