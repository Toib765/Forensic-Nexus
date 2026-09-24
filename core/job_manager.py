import threading
import time
import uuid
from typing import Any


class InMemoryJobStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._jobs: dict[str, dict[str, Any]] = {}

    def create(self, operation: str, requested_by: str, context: dict[str, Any] | None = None):
        job_id = f"ASYNC-{operation}-{uuid.uuid4().hex[:10].upper()}"
        payload = {
            "job_id": job_id,
            "operation": operation,
            "requested_by": requested_by,
            "status": "QUEUED",
            "created_at": time.time(),
            "started_at": None,
            "finished_at": None,
            "error": None,
            "result": None,
            "context": context or {},
        }
        with self._lock:
            self._jobs[job_id] = payload
        return payload.copy()

    def mark_running(self, job_id: str):
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job["status"] = "RUNNING"
            job["started_at"] = time.time()

    def mark_success(self, job_id: str, result: dict[str, Any]):
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job["status"] = "COMPLETED"
            job["result"] = result
            job["finished_at"] = time.time()

    def mark_failed(self, job_id: str, error: str):
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job["status"] = "FAILED"
            job["error"] = error
            job["finished_at"] = time.time()

    def get(self, job_id: str):
        with self._lock:
            job = self._jobs.get(job_id)
            return job.copy() if job else None


job_store = InMemoryJobStore()
