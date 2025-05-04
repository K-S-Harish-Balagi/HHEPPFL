import asyncio

class SmartSemaphore:
    def __init__(self, initial):
        self._initial = initial      # Original threshold
        self._active = initial        # Current active clients
        self._semaphore = asyncio.Semaphore(initial)
        self._lock = asyncio.Lock()
        self._pending_releases = 0    # Count of drops that must be released at round end

    async def wait(self):
        await self._semaphore.acquire()

    async def signal(self):
        async with self._lock:
            self._semaphore.release()

    async def drop(self):
        async with self._lock:
            self._active -= 1
            self._pending_releases += 1
            print(f"[SERVER] Client dropped. Active clients now: {self._active}. Pending releases: {self._pending_releases}")

    async def finalize_round(self):
        """At the end of the round, release all pending drops."""
        async with self._lock:
            for _ in range(self._pending_releases):
                self._semaphore.release()
            print(f"[SERVER] Finalized round. Released {self._pending_releases} pending drops.")
            self._pending_releases = 0
            self._active = self._initial  # Reset active to threshold for next round

    def active(self):
        return self._active
