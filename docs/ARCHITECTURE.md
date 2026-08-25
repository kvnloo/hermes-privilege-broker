# Architecture

1. Catalog loader validates exact schema, typed bounded slots, ownership/modes/ancestors, ELF identity, and canonical SHA-256 catalog digest.
2. Two Unix listeners authenticate their distinct account sets from kernel peer credentials and process start time. Production packaging assigns requester socket group `hermes-privilege-requester` and operator socket group `hermes-privilege-operator`; neither group reaches the other socket.
3. Request ledger records `pending`; operator decision records `approved`; an internal random capability is never sent through requester-controlled fields.
4. Consume atomically records `reserved`, opens and hashes the executable, records `running`, and executes through the descriptor. Terminal `result` is then fsynced.
5. Startup maps `reserved|running` to `ambiguous` and has no persisted grants.

Integration contract for a later Hermes plugin: send exact UTF-8 JSON `{request_id,operation_id,slots,reason}` to the requester socket; never accept command/argv/env/cwd; poll status by request ID; treat `ambiguous` as a hard human-reconciliation state. Native Hermes approval may authorize submission, but only the separately authenticated operator frontend may issue the broker decision.
