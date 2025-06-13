import logging
import os
from dotenv import load_dotenv

load_dotenv()

def setup_debug_logging():
    """Setup debug logging configuration."""
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s [%(levelname)s] %(name)s:%(lineno)d: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

def log_environment_info():
    """Log environment information."""
    logger = logging.getLogger(__name__)
    logger.info("Environment Info:")
    logger.info("Python Version: %s", os.sys.version)
    logger.info("Working Directory: %s", os.getcwd())
    logger.info("Environment Variables:")
    for key in sorted(os.environ):
        if key.startswith('FLASK_') or key.startswith('SQLALCHEMY_'):
            logger.info("  %s: %s", key, os.environ[key])
