from __future__ import annotations


class UnsafeCommandError(RuntimeError):
    pass


class ReadOnlyCommandGuard:
    """Hard allow-list for Salesforce CLI commands used by Dementor.

    The guard is intentionally conservative. If a command is not explicitly allowed,
    it is rejected even when it might be read-only.
    """

    ALLOWED_PREFIXES = (
        ("sf", "org", "display"),
        ("sf", "org", "list", "limits"),
        ("sf", "org", "list", "metadata-types"),
        ("sf", "org", "list", "metadata"),
        ("sf", "org", "list", "sobject", "record-counts"),
        ("sf", "data", "query"),
        ("sf", "api", "request", "rest"),
        ("sf", "project", "generate", "manifest"),
        ("sf", "project", "retrieve", "start"),
        ("sf", "code-analyzer", "run"),
        ("sf", "code-analyzer", "rules"),
        ("sf", "plugins"),
        ("sf", "version"),
    )

    BLOCKED_TOKENS = {
        "deploy", "delete", "create", "update", "upsert", "insert", "destroy",
        "quick", "validate", "cancel", "apex", "execute", "run-task"
    }

    # Exceptions to token blocking: 'code-analyzer run' is read-only static analysis.
    SAFE_EXACT = {("sf", "code-analyzer", "run")}

    @classmethod
    def validate(cls, args: list[str]) -> None:
        normalized = tuple(a.strip().lower() for a in args if a.strip())
        if not normalized or normalized[0] != "sf":
            raise UnsafeCommandError("Only Salesforce CLI ('sf') commands are permitted.")

        if normalized[:3] in cls.SAFE_EXACT:
            return

        if normalized[:4] == ("sf", "api", "request", "rest"):
            method = "get"
            for flag in ("--method", "-x"):
                if flag in normalized:
                    idx = normalized.index(flag)
                    if idx + 1 >= len(normalized):
                        raise UnsafeCommandError("REST method flag is missing a value.")
                    method = normalized[idx + 1]
            if method != "get":
                raise UnsafeCommandError(f"Only GET is allowed for sf api request rest; got {method.upper()}.")
            # Bodies and request files could hide a mutating method; disallow them entirely.
            if any(x in normalized for x in ("--body", "-b", "--file", "-f")):
                raise UnsafeCommandError("REST body/file requests are not allowed in read-only mode.")
            return

        if any(token in cls.BLOCKED_TOKENS for token in normalized):
            raise UnsafeCommandError(f"Blocked potentially mutating command: {' '.join(args)}")

        if not any(normalized[: len(prefix)] == prefix for prefix in cls.ALLOWED_PREFIXES):
            raise UnsafeCommandError(f"Command is not in the read-only allow-list: {' '.join(args)}")
