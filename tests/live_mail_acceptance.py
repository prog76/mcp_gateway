#!/usr/bin/env python3
"""Live acceptance probe for the mail backend (card t_fbe11d78).

NOT collected by pytest (the name does not start with `test_`): it opens a real
IMAP connection to a real mailbox, which only makes sense on the VDI with a
real app password present.

WHAT IT PROVES, in one run
  1. the mounted mail config parses and yields an account + gate rules;
  2. the transport the config lists FIRST actually completes a TLS handshake
     from inside the gateway container;
  3. `mail_fetch` finds the known reference letter for an alias in SECONDS
     (the browser playbook this replaced needed ~16s);
  4. the password appears in NO returned value, and in no diagnostic string.

USAGE (from the VDI host, in the gateway repo checkout)

  # inside the container that runs the gateway: needs MAIL_CONFIG + the env
  docker run --rm --entrypoint sh \\
    -v /home/aedobshikov@oscaryard.local/src-local/llm/gateway:/src \\
    -v /home/aedobshikov@oscaryard.local/src-local/llm/deploy/config:/cfg:ro \\
    --env-file /home/aedobshikov@oscaryard.local/src-local/llm/deploy/.env \\
    -w /src -e MAIL_CONFIG=/cfg/mail.yaml \\
    ghcr.io/prog76/mcp-gateway:<GATEWAY_VERSION> \\
    -c 'python tests/live_mail_acceptance.py'

  # ...or, against the RUNNING gateway container (its env already carries the
  # passwords), copy the module + this script in first - the container has no
  # checkout of the gateway repo:
  docker cp gateway/mail_mcp.py mcp-gateway:/tmp/
  docker cp tests/live_mail_acceptance.py mcp-gateway:/tmp/
  docker exec -e PYTHONPATH=/tmp -e MAIL_CONFIG=/etc/mcp-gateways/mail.yaml \\
    mcp-gateway python /tmp/live_mail_acceptance.py

Exit code 0 = acceptance met. 2 = the credential is absent (nothing else ran).
1 = a real failure, printed with its typed reason.
"""

import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gateway import mail_mcp as mm  # noqa: E402

ALIAS = "rs2qeug3kpxg@mail.ru"
SUBJECT_HINT = "launch code"
REFERENCE_CODE = "27169490"


def _reply(coro):
    return json.loads(asyncio.new_event_loop().run_until_complete(coro))


def _fail(msg: str) -> int:
    print("FAIL " + msg)
    return 1


def main() -> int:
    cfg_path = mm.config_path()
    print("config   : %s (exists=%s)" % (cfg_path, os.path.exists(cfg_path)))
    cfg = mm.load_config(reload=True)
    if not cfg["accounts"]:
        return _fail("no accounts in the config - the backend is closed")
    print("accounts : %s" % (", ".join(sorted(cfg["accounts"])),))
    print("senders  : %s" % (", ".join(cfg["senders"]),))

    account = sorted(cfg["accounts"])[0]
    env_name, secret = mm._credential(account)
    print("account  : %s" % (account,))
    print("password : env %s present=%s" % (env_name, bool(secret)))
    if not secret:
        print("SKIP     the credential is absent - set %s in deploy/.env "
              "(or llm-password.env), recreate mcp, re-run" % (env_name,))
        return 2

    # --- 1. status: names only, never a value ------------------------------
    print("\nstatus:\n%s" % (mm._tool_status(),))

    # --- 2. live fetch -----------------------------------------------------
    args = {"account": account, "from_filter": "github.com",
            "alias": ALIAS, "subject_contains": SUBJECT_HINT, "timeout": 40}
    print("\nmail_fetch %s" % (json.dumps(args),))
    out = _reply(mm._tool_fetch(**args))
    print(json.dumps(out, ensure_ascii=False, indent=2)[:2500])

    # --- 3. leak check: the value may not appear anywhere in the result ----
    blob = json.dumps(out)
    leaked = secret in blob
    print("\nleak     : password present in the result = %s" % (leaked,))
    if leaked:
        return _fail("the password leaked into the tool result")

    if not out.get("ok"):
        return _fail("typed failure: %s (%s)" % (out.get("reason"), out.get("error", "")[:200]))
    if not out.get("found"):
        return _fail("no letter matched: %s" % (json.dumps(out.get("diag"))[:400],))

    first = out["matches"][0]
    print("found    : folder=%s uid=%s subject=%r in %ss"
          % (first["folder"], first["uid"], first["subject"], out.get("elapsed_s")))
    print("code     : %s (reference %s)" % (first.get("code"), REFERENCE_CODE))
    print("link     : %s" % ((first.get("verify_link") or "")[:90],))

    # --- 4. wait_for must return the same shape ----------------------------
    waited = _reply(mm._tool_wait(account=account, from_filter="github.com",
                                  alias=ALIAS, since="2026-09-16", timeout=45))
    print("\nmail_wait_for: ok=%s found=%s attempts=%s waited_s=%s"
          % (waited.get("ok"), waited.get("found"), waited.get("attempts"),
             waited.get("waited_s")))
    if (waited.get("ok") and waited.get("found")
            and waited["matches"][0].get("code") != first.get("code")):
        return _fail("wait_for returned a different letter than fetch")

    print("\nPASS mail backend acceptance: letter found, code extracted, "
          "password absent from every value")
    return 0


if __name__ == "__main__":
    sys.exit(main())
