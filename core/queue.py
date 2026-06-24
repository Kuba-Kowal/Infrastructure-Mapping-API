from dataclasses import dataclass
from collections import deque

@dataclass
class Queue:
    queue: deque[str]
    seen: set[str]

    def next_item_in_queue(self) -> str:
        next_item = self.queue.popleft()
        self.seen.add(next_item)

        return next_item

    def add_to_queue(self, domains: list[str]) -> None:
        if domains:
            for domain in domains:
                if domain in self.seen or domain in self.queue:
                    continue
                self.queue.append(domain)