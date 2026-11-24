"""Event bus that pushes revocations and role changes to enforcement points."""


class EventBus:
    def __init__(self, clock, rng, delay_mean: float = 1.0, delay_jitter: float = 0.5,
                 heartbeat_every: float = 2.0):
        self.clock = clock
        self.rng = rng
        self.delay_mean = delay_mean
        self.delay_jitter = delay_jitter
        self.heartbeat_every = heartbeat_every
        self.subscribers = []
        self.partitioned = set()   # subscriber names currently cut off
        self._queued = {}          # name -> events held during a partition

    def subscribe(self, subscriber):
        self.subscribers.append(subscriber)

    def _deliver(self, sub, event):
        delay = max(0.05, self.rng.gauss(self.delay_mean, self.delay_jitter))
        self.clock.after(delay, sub.on_event, event)

    def publish(self, event: dict):
        for sub in self.subscribers:
            if sub.name in self.partitioned:
                # Durable events are held and delivered when the partition heals.
                if event["type"] != "heartbeat":
                    self._queued.setdefault(sub.name, []).append(event)
                continue
            self._deliver(sub, event)

    def start_heartbeats(self):
        self.clock.every(self.heartbeat_every, self.publish, {"type": "heartbeat"})

    def partition(self, name: str):
        self.partitioned.add(name)

    def heal(self, name: str):
        self.partitioned.discard(name)
        for sub in self.subscribers:
            if sub.name == name:
                for event in self._queued.pop(name, []):
                    self._deliver(sub, event)
