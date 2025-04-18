import logging
import logging.config


def setup_logging():
    try:
        logging_config = {
            'version': 1,
            'disable_existing_loggers': False,
            'formatters': {
                'standard': {
                    'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
                },
            },
            'handlers': {
                'console': {
                    'level': 'DEBUG',
                    'class': 'logging.StreamHandler',
                    'formatter': 'standard'
                },
                'file': {
                    'level': 'DEBUG',
                    'class': 'logging.FileHandler',
                    'formatter': 'standard',
                    'filename': 'project.log',
                    'mode': 'a',
                },
            },
            'loggers': {
                '': {
                    'handlers': ['console', 'file'],
                    'level': 'DEBUG',
                    'propagate': True
                },
            }
        }
        logging.config.dictConfig(logging_config)
        logging.getLogger(__name__).info("Logging successfully configured.")
    except Exception as e:
        # Fallback to basic logging if configuration fails
        logging.basicConfig(level=logging.ERROR)
        logging.getLogger(__name__).exception("Failed to configure logging. Using basic configuration.")
