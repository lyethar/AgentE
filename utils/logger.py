import logging
import sys
from datetime import datetime
from pathlib import Path


class ColorFormatter(logging.Formatter):
    COLORS = {
        "DEBUG":    "\033[36m",   # Cyan
        "INFO":     "\033[32m",   # Green
        "WARNING":  "\033[33m",   # Yellow
        "ERROR":    "\033[31m",   # Red
        "CRITICAL": "\033[35m",   # Magenta
    }
    RESET = "\033[0m"
    BOLD  = "\033[1m"

    def format(self, record):
        color = self.COLORS.get(record.levelname, "")
        record.levelname = f"{color}{self.BOLD}{record.levelname:<8}{self.RESET}"
        record.name      = f"\033[90m{record.name}\033[0m"
        return super().format(record)


def setup_logger(name: str, output_dir: Path | None = None, verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(ColorFormatter(
        fmt="%(asctime)s  %(levelname)s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    ))
    logger.addHandler(console)

    if output_dir:
        log_file = output_dir / "agente.log"
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(
            fmt="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        logger.addHandler(file_handler)

    return logger
