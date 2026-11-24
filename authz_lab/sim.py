"""A tiny discrete-event scheduler.

Simulated time lets the experiments model hour-long token lifetimes and
thousands of requests in a few seconds of real time, and makes every run
reproducible from a seed.
"""
import heapq
import itertools


class Scheduler:
    def __init__(self, start: float = 0.0):
        self.now = start
        self._queue = []
        self._seq = itertools.count()

    def at(self, t: float, fn, *args):
        """Run fn(*args) at absolute simulated time t."""
        heapq.heappush(self._queue, (t, next(self._seq), fn, args))

    def after(self, delay: float, fn, *args):
        self.at(self.now + delay, fn, *args)

    def every(self, interval: float, fn, *args, start: float | None = None):
        """Run fn(*args) periodically, starting at `start` (default: now)."""
        def tick():
            fn(*args)
            self.after(interval, tick)
        self.at(self.now if start is None else start, tick)

    def run(self, until: float, stop=lambda: False):
        """Process events up to time `until`, or until stop() returns True."""
        while self._queue and self._queue[0][0] <= until:
            t, _, fn, args = heapq.heappop(self._queue)
            self.now = t
            fn(*args)
            if stop():
                return
        self.now = until
