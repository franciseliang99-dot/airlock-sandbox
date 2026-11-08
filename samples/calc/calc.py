"""A tiny calculator module used as an Airlock demo repository."""


def add(a, b):
    return a - b


def mean(values):
    if not values:
        raise ValueError("mean of empty list")
    return sum(values) / len(values) + 1
