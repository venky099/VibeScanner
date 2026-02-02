"""
Centralized logging configuration for VibeScanner
Provides consistent logging across all modules with proper formatting and levels
"""

import logging
import logging.handlers
import os
from datetime import datetime

# Create logs directory if it doesn't exist
LOGS_DIR = os.path.join(os.path.dirname(__file__), 'logs')
if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR)

# Log file paths
LOG_FILE = os.path.join(LOGS_DIR, f'vibescanner_{datetime.now().strftime("%Y%m%d")}.log')
ERROR_LOG_FILE = os.path.join(LOGS_DIR, f'vibescanner_errors_{datetime.now().strftime("%Y%m%d")}.log')

# Define log format
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
SIMPLE_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'

def get_logger(name: str, level=logging.DEBUG) -> logging.Logger:
    """
    Get a configured logger instance for any module.
    
    Args:
        name: Logger name (typically __name__)
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Avoid duplicate handlers
    if logger.handlers:
        return logger
    
    # Console handler (INFO level and above)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(SIMPLE_FORMAT)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler (DEBUG level and above)
    file_handler = logging.handlers.RotatingFileHandler(
        LOG_FILE,
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(LOG_FORMAT)
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    # Error file handler (ERROR level and above)
    error_handler = logging.FileHandler(ERROR_LOG_FILE)
    error_handler.setLevel(logging.ERROR)
    error_formatter = logging.Formatter(LOG_FORMAT)
    error_handler.setFormatter(error_formatter)
    logger.addHandler(error_handler)
    
    return logger


def setup_flask_logging(app):
    """
    Setup logging for Flask application.
    
    Args:
        app: Flask application instance
    """
    flask_logger = get_logger('flask.app')
    app.logger = flask_logger
    
    # Remove default Flask handlers to avoid duplication
    app.logger.handlers = []
    
    # Add configured handlers
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(SIMPLE_FORMAT)
    console_handler.setFormatter(console_formatter)
    app.logger.addHandler(console_handler)
    
    file_handler = logging.handlers.RotatingFileHandler(
        LOG_FILE,
        maxBytes=10 * 1024 * 1024,
        backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(LOG_FORMAT)
    file_handler.setFormatter(file_formatter)
    app.logger.addHandler(file_handler)


# Log levels helper
DEBUG = logging.DEBUG
INFO = logging.INFO
WARNING = logging.WARNING
ERROR = logging.ERROR
CRITICAL = logging.CRITICAL
