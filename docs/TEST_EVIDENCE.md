# TDD evidence

Initial RED: `python -m pytest tests/test_broker.py -q` failed during collection because production modules did not exist.

Subsequent focused RED/GREEN cycles covered catalog ownership/types, shebang and renamed interpreter rejection, split roles, kernel peer credentials, request mutation/expiry/replay, restart ambiguity, ledger failure, descriptor-bound path swap, output cap, descendant timeout, inert Telegram rendering, and exact harmless execution.

Final command and exact result are refreshed before release and recorded in the release commit/kanban handoff. All tests run unprivileged against disposable temporary directories; no sudo or live installation is used.
