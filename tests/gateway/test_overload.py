"""Graceful overload admission-control unit tests (FR-047).

Pure logic, no database. Verifies that a Limiter admits up to max_concurrent
in flight plus max_queue waiting, that the next acquire past both is shed with a
retryable Overloaded carrying a retry hint, that release frees a slot and
promotes a waiter, and that shedding is never a silent drop or a protection
bypass -- it always returns a retryable signal and never exceeds capacity.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from erebus.gateway.overload import (
    DEFAULT_RETRY_AFTER_SECONDS,
    Limiter,
    Overloaded,
    Token,
)

_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _expect_overloaded(limiter):
    """Acquire and assert it sheds with a retryable Overloaded; return the exc."""
    try:
        limiter.acquire()
    except Overloaded as exc:
        return exc
    raise AssertionError("expected Overloaded, got admission")


def main():
    print("\n=== Gateway graceful overload (FR-047) ===\n")

    # --- Construction guards ----------------------------------------------
    for bad in (0, -1):
        try:
            Limiter(max_concurrent=bad)
            raise AssertionError("expected ValueError")
        except ValueError:
            check(f"max_concurrent={bad} rejected", True)
    try:
        Limiter(max_concurrent=1, max_queue=-1)
        raise AssertionError("expected ValueError")
    except ValueError:
        check("negative max_queue rejected", True)

    # --- Fill slots, then fill queue, then shed ---------------------------
    lim = Limiter(max_concurrent=2, max_queue=1)
    check("capacity == max_concurrent + max_queue", lim.capacity == 3)
    check("starts empty", lim.running == 0 and lim.queued == 0)

    t1 = lim.acquire()
    t2 = lim.acquire()
    check("two acquires fill both slots RUNNING",
          t1.state == "RUNNING" and t2.state == "RUNNING")
    check("running==2 queued==0 after filling slots",
          lim.running == 2 and lim.queued == 0)

    t3 = lim.acquire()
    check("third acquire is QUEUED (slots full, queue free)", t3.state == "QUEUED")
    check("running==2 queued==1 after queue fills", lim.running == 2 and lim.queued == 1)

    # Both slots and the queue are now full: next acquire must shed.
    exc = _expect_overloaded(lim)
    check("over-capacity acquire raises Overloaded", isinstance(exc, Overloaded))
    check("Overloaded is an Exception subclass", isinstance(exc, Exception))
    check("shed signal is retryable=True", exc.retryable is True)
    check("shed carries a retry hint > 0", exc.retry_after_seconds > 0)
    check("retry hint defaults to DEFAULT_RETRY_AFTER_SECONDS",
          exc.retry_after_seconds == DEFAULT_RETRY_AFTER_SECONDS)

    # Never silently drops protection: shedding does NOT admit work. The internal
    # bound must be unchanged after a shed (no bypass slot was created).
    check("shed admitted nothing: running==2 queued==1 unchanged",
          lim.running == 2 and lim.queued == 1)
    check("never exceeds capacity bound", lim.running + lim.queued <= lim.capacity)

    # --- release frees a slot and promotes the waiter --------------------
    lim.release(t1)
    check("after releasing a running slot, queued waiter is promoted",
          lim.running == 2 and lim.queued == 0)
    check("promoted token's state flipped to RUNNING", t3.state == "RUNNING")

    # With the queue drained but slots full, next acquire queues again (no shed).
    t4 = lim.acquire()
    check("acquire after promotion re-queues (slots still full)", t4.state == "QUEUED")
    # Now full again -> shed.
    check("full again sheds retryably", _expect_overloaded(lim).retryable is True)

    # Releasing the promoted (formerly queued) token frees a real running slot,
    # proving promotion accounted the resource correctly (no leak).
    lim.release(t3)
    check("releasing promoted token frees a running slot then promotes t4",
          lim.running == 2 and lim.queued == 0 and t4.state == "RUNNING")

    # --- release is idempotent (error paths may double-release) ----------
    before = (lim.running, lim.queued)
    lim.release(t3)  # already released
    check("double release is a no-op", (lim.running, lim.queued) == before)

    # --- pure no-queue limiter: shedding with zero queue -----------------
    strict = Limiter(max_concurrent=1, max_queue=0)
    s1 = strict.acquire()
    check("single slot fills", s1.state == "RUNNING" and strict.running == 1)
    shed = _expect_overloaded(strict)
    check("zero-queue limiter sheds immediately past concurrency", shed.retryable)
    strict.release(s1)
    check("release reopens the single slot", strict.running == 0)
    s2 = strict.acquire()
    check("can acquire again after release", s2.state == "RUNNING")

    # --- custom retry hint flows through to the shed signal --------------
    hinted = Limiter(max_concurrent=1, retry_after_seconds=5.0)
    hinted.acquire()
    check("custom retry hint propagates to Overloaded",
          _expect_overloaded(hinted).retry_after_seconds == 5.0)

    # --- no process-global state: distinct limiters are independent (FR-043)
    a = Limiter(max_concurrent=1)
    b = Limiter(max_concurrent=1)
    a.acquire()
    check("filling one limiter does not affect another", b.running == 0)
    tb = b.acquire()
    check("second limiter admits independently", tb.state == "RUNNING")

    # --- Token carries no payload, only identity + state -----------------
    check("Token fields are id + state only",
          set(Token(id=1, state="RUNNING").__dict__) == {"id", "state"})

    # --- Overloaded constructed directly is always retryable -------------
    direct = Overloaded()
    check("Overloaded() defaults retryable=True", direct.retryable is True)
    check("Overloaded() carries default retry hint",
          direct.retry_after_seconds == DEFAULT_RETRY_AFTER_SECONDS)

    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
