import logging

def createLogger(name: str) -> logging.Logger:
    logger = logging.Logger(name=name)
    logger.setLevel(logging.INFO)

    handler = logging.FileHandler(f"logs/{name}.log", "w")
    formatter = logging.Formatter("%(name)s %(asctime)s %(levelname)s %(message)s")

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger
