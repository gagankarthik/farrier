"""farrier CLI."""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import date
from pathlib import Path

from farrier.core import policy


def _dashboard_dev_command(base: str) -> str:
    """Return the platform-appropriate command for starting the web dashboard."""
    if sys.platform == "win32":
        return f'cd web; $env:FARRIER_API_URL="{base}"; npm run dev'
    return f"cd web && FARRIER_API_URL={base} npm run dev"


def _engine(args):
    from farrier.core.engine import Engine
    return Engine(Path(args.data))


def cmd_serve(args):
    import uvicorn

    from farrier.api.app import create_app
    from farrier.demo import devices_dir
    if args.host not in ("127.0.0.1", "localhost") and not os.environ.get("FARRIER_API_TOKEN"):
        sys.exit("refusing to listen on a non-loopback address without FARRIER_API_TOKEN set")
    if devices_dir(Path(args.data)).exists():
        sys.exit(f"{args.data} holds the simulated demo estate; serve a real install from another --data directory")
    import signal
    import time

    eng = _engine(args)
    # uvicorn handles SIGTERM itself (stop accepting, drain requests for --grace seconds, run the
    # app shutdown) and then re-raises the signal to whatever handler was installed before it.
    # Installing ours first means that re-raise lands here instead of killing the process, so we
    # can let the running renewal tick finish and hand the leader lease over cleanly.
    signal.signal(signal.SIGTERM, lambda *_: None)
    base = f"http://{args.host}:{args.port}"
    print(f"farrier engine API on {base}/api (OpenAPI at {base}/docs); dashboard: `docker compose up` runs both, "
          f"or {_dashboard_dev_command(base)}", flush=True)
    deadline = time.monotonic() + 2 * args.grace
    try:
        uvicorn.run(create_app(eng, tick_seconds=args.tick), host=args.host, port=args.port,
                    timeout_graceful_shutdown=args.grace)
    finally:
        if not eng.shutdown(timeout=deadline - time.monotonic()):
            print("farrier: renewal tick still running at shutdown deadline; exiting anyway "
                  "(its compare-and-set writes are safe to resume on another replica)", file=sys.stderr)
        eng.store.close()


def cmd_db_migrate(args):
    from farrier.db.dialects import redact_url
    from farrier.db.store import Store
    src = Store(Path(args.data), url=args.source)
    dst = Store(Path(args.data), url=args.to)
    print(f"copying {redact_url(src.url)} ({src.backend}) -> {redact_url(dst.url)} ({dst.backend})")
    counts = src.copy_to(dst, progress=lambda t, n, total: print(f"  {t:<13} {n}/{total}", end="\r"))
    print(" " * 40, end="\r")
    for t, n in counts.items():
        print(f"  {t:<13} {n} rows")
    print(f"done; schema version {dst.schema_version()}. Sealed keys were copied as ciphertext: every replica\n"
          f"needs the same master key (FARRIER_MASTER_KEY or {Path(args.data) / 'master.key'}).\n"
          f"Point FARRIER_DATABASE_URL at the new database and restart.")


def cmd_backup(args):
    from farrier.db.backup import backup
    from farrier.db.store import Store
    from farrier.storage import from_url
    url = backup(Store(Path(args.data)), from_url(args.to, Path(args.data)))
    print(f"backup written to {url}\nSealed keys and secrets stay sealed: restoring needs the same master key.")


def cmd_restore(args):
    from farrier.db.backup import restore, split_object_url
    from farrier.db.store import Store
    storage, key = split_object_url(args.source)
    data = storage.get(key)
    if data is None:
        sys.exit(f"no backup at {args.source}")
    dst = Store(Path(args.data), url=args.to)
    for t, n in restore(dst, data, allow_unsigned=args.allow_unsigned).items():
        print(f"  {t:<13} {n} rows")
    print("done. Every replica needs the master key the backup was sealed with.")


def cmd_demo(args):
    import uvicorn

    from farrier.api.app import create_app
    from farrier.demo import devices_dir, start
    data = Path(args.data)
    if os.environ.get("FARRIER_DATABASE_URL") or ((data / "farrier.db").exists() and not devices_dir(data).exists()):
        sys.exit(f"{args.data} (or FARRIER_DATABASE_URL) holds a real install; run the demo with another --data "
                 "directory and no FARRIER_DATABASE_URL")
    if args.host not in ("127.0.0.1", "localhost") and not os.environ.get("FARRIER_API_TOKEN"):
        sys.exit("refusing to listen on a non-loopback address without FARRIER_API_TOKEN set")
    eng, srv = start(Path(args.data), args.simulate_date)
    print(f"demo estate: {len(eng.store.endpoints())} endpoints served by SNI on 127.0.0.1:{srv.port}")
    eng.tick()
    print(f"api:         http://{args.host}:{args.port}/api  (OpenAPI docs at /docs)")
    print(f"dashboard:   {_dashboard_dev_command(f'http://{args.host}:{args.port}')}", flush=True)
    uvicorn.run(create_app(eng, tick_seconds=args.tick), host=args.host, port=args.port, log_level="warning")


def cmd_scan(args):
    from farrier.core.discovery import expand_targets, scan
    results = scan(expand_targets(" ".join(args.targets), limit=1 << 18), timeout=args.timeout)
    now = policy.utcnow()
    for r in sorted(results, key=lambda r: (r.cert is None, r.cert and r.cert.not_after)):
        if r.cert:
            dl = policy.days_left(r.cert.not_after, now)
            print(f"{r.sni or r.host}:{r.port:<6} {dl:7.1f}d  {r.cert.lifetime_days:4d}d life  "
                  f"{r.cert.subject_cn}  [{r.cert.issuer}]")
        elif args.verbose:
            print(f"{r.host}:{r.port:<6} -- {r.error}")
    if args.register:
        out = _engine(args).register_scan(results)
        print(f"registered: {out['new']} new, {out['seen']} seen")


def cmd_tick(args):
    print(json.dumps(_engine(args).tick(), indent=2))


def cmd_import(args):
    eng = _engine(args)
    from farrier.connectors import make_connector
    from farrier.core.scheduler import check as check_window
    items = json.loads(Path(args.file).read_text())
    for ep in items:
        make_connector(ep.get("connector", "manual"), ep.get("connector_config", {}), eng.data_dir)
        check_window(ep.get("window") or {})
        eid = eng.store.upsert_endpoint(ep)
        cert = eng.observe(eng.store.endpoint(eid))
        print(f"{ep['name']:<40} {'ok, ' + str(round(policy.days_left(cert.not_after))) + 'd left' if cert else 'no TLS'}")


def cmd_forecast(args):
    print(f"{args.certs} certificates, {args.manual:.0%} need a human, {args.minutes:.0f} min each\n")
    print(f"{'from':<12}{'max life':>9}{'renew every':>13}{'per year':>10}{'per work day':>14}{'manual h/yr':>13}{'FTE':>6}")
    for f in policy.forecast_timeline(args.certs, args.manual, args.minutes, args.lead):
        print(f"{f['on']:<12}{f['lifetime_days']:>8}d{f['interval_days']:>12}d{f['renewals_per_year']:>10}"
              f"{f['per_working_day']:>14}{f['manual_hours_per_year']:>13}{f['manual_fte']:>6}")
    naive = policy.forecast(args.certs, date(2029, 3, 15), early=False)
    print(f"\nnaive 47-day figure (renew on expiry day): {naive.renewals_per_year}/yr = "
          f"{naive.per_calendar_day}/calendar day = {naive.per_working_day}/working day")


def cmd_mcp(args):
    """MCP over stdio for Claude Desktop/Code, Gemini CLI, Codex. stdout carries only protocol messages."""
    from farrier.api.mcp import run_stdio
    run_stdio(_engine(args))


NOT_FOUND = 4       # exit code for "no such endpoint", the CLI's 404


def _emit(args, obj, text) -> None:
    """``--json`` prints the payload the matching API route returns; otherwise the lines ``text()`` yields."""
    if args.json:
        print(json.dumps(obj, indent=2, default=str))
    else:
        for line in text():
            print(line)


def _endpoint(eng, ref: str) -> dict:
    """An inventory endpoint by name, or by id when ``ref`` is a number."""
    ep = eng.store.endpoint(int(ref)) if ref.isdigit() else None
    ep = ep or next((e for e in eng.store.endpoints() if e["name"] == ref), None)
    if not ep:
        print(f"farrier: no endpoint named or numbered {ref!r}", file=sys.stderr)
        sys.exit(NOT_FOUND)
    return ep


def cmd_version(args):
    from farrier import __version__
    print(f"farrier {__version__}")


def cmd_ssh_scan(args):
    from farrier.ssh import access, db, scan
    try:
        targets = access.expand_hosts(args.targets, 22)
    except access.Invalid as e:
        sys.exit(f"farrier: {e}")
    if not targets:
        sys.exit("farrier: no targets")
    eng = _engine(args)
    out = scan.scan(eng.store, targets)
    eng.store.log(f"ssh scan of {len(targets)} targets by cli: {out['ssh']} answered")
    hosts = [scan.host_view(h) for t in targets if (h := db.host_by_addr(eng.store, *t))]

    def text():
        yield f"{'host':<24}{'banner':<34}{'host keys':<32}{'pqc kex':>8}{'findings':>9}"
        for h in hosts:
            keys = ", ".join(f"{k['type']} {k['bits']}" for k in h["host_keys"]) or "-"
            yield (f"{h['host'] + ':' + str(h['port']):<24}{(h['banner'] or h['error'] or '-')[:33]:<34}"
                   f"{keys[:31]:<32}{'yes' if h['pqc_kex'] else 'no':>8}{len(h['findings']):>9}")
        for e in out["errors"]:
            yield f"{e['host']}:{e['port']}  -- {e['error']}"
        yield f"{out['scanned']} scanned, {out['ssh']} answered SSH, {out['saved']} stored"
    _emit(args, out | {"hosts": hosts}, text)


def cmd_ssh_keys(args):
    from farrier.api.ssh_routes import key_view
    from farrier.ssh import db
    keys = [key_view(k) for k in db.keys(_engine(args).store)]

    def text():
        if not keys:
            yield "no authorized keys collected yet (add an SSH access profile, then run a collection)"
        for k in keys:
            yield (f"{k['id']:>5}  {k['user']}@{k['host']}:{k['port']}  {k['type']} {k['bits']}  "
                   f"{k['fingerprint_sha256']}  {k['comment']}")
            for f in k["findings"]:
                yield f"       {f['severity']:<8} {f['detail']}"
    _emit(args, keys, text)


def cmd_crypto_scan(args):
    from farrier.core.discovery import expand_targets
    from farrier.crypto import repository, service
    from farrier.crypto.probe import target_label
    try:
        targets = expand_targets(" ".join(args.targets), limit=service.MAX_TARGETS)
        if not targets:
            sys.exit("farrier: no targets")
        eng = _engine(args)
        timeout = args.timeout if args.timeout is not None else float(eng.settings.get("scan_timeout", 5.0))
        out = service.scan_targets(eng.store, targets, timeout=timeout)
    except ValueError as e:
        sys.exit(f"farrier: {e}")
    eng.store.log(f"crypto scan of {len(targets)} targets by cli")
    wanted = {target_label(*t) for t in targets}
    assets = [a for a in repository.tls_assets(eng.store) if a["target"] in wanted]

    def text():
        for a in assets:
            yield a["target"]
            if a["error"]:
                yield f"  error:        {a['error']}"
            yield f"  TLS versions: {', '.join(a['protocol_versions']) or '-'}"
            yield f"  key exchange: {a['key_exchange'] or '-'}{' (post-quantum)' if a['pqc_key_exchange'] else ''}"
            yield f"  PQC status:   {a['pqc']['status']}"
            for r in a["pqc"]["reasons"]:
                yield f"    - {r}"
        yield f"{out['scanned']} scanned, {out['stored']} stored"
    _emit(args, out | {"assets": assets}, text)


def cmd_crypto_summary(args):
    from farrier.crypto import service
    s = service.summary(_engine(args).store)

    def text():
        yield f"{s['total']} assets"
        yield "PQC status:    " + ", ".join(f"{k} {v}" for k, v in s["by_status"].items())
        yield "key algorithm: " + (", ".join(f"{k} {v}" for k, v in s["by_key_algorithm"].items()) or "-")
        yield "weak:          " + ", ".join(f"{k} {v}" for k, v in s["weak"].items())
    _emit(args, s, text)


def cmd_crypto_cbom(args):
    from farrier.crypto import service
    doc = json.dumps(service.cbom(_engine(args).store), indent=2)
    if args.output:
        Path(args.output).write_text(doc + "\n", encoding="utf-8")
        print(f"CycloneDX CBOM written to {args.output}", file=sys.stderr)
    else:
        print(doc)


def cmd_certs_show(args):
    from farrier.crypto import certificate
    eng = _engine(args)
    ep = _endpoint(eng, args.endpoint)
    d = certificate.details(eng.store, ep)

    def text():
        if not d["observed_at"]:
            yield f"{ep['name']}: no certificate observed yet (run farrier tick)"
            return
        key = d["key"] or {}
        rows = [("endpoint", f"{ep['name']} (id {ep['id']}, {ep['host']}:{ep['port']})"),
                ("subject", d["subject"] or d["common_name"]), ("SANs", ", ".join(d["sans"])),
                ("issuer", d["issuer"]), ("serial", d["serial"]),
                ("valid", f"{d['not_before']} -> {d['not_after']}"), ("days left", d["days_left"]),
                ("key", " ".join(str(v) for v in key.values() if v not in (None, ""))),
                ("signature", d["signature_algorithm"]), ("sha256", d["fingerprints"]["sha256"]),
                ("self-signed", d["self_signed"]), ("chain", f"{len(d['chain'])} certificate(s)"),
                ("renewals", len(d.get("renewals") or [])), ("health", (d.get("health") or {}).get("grade")),
                ("observed", d["observed_at"])]
        for k, v in rows:
            yield f"{k + ':':<13}{'-' if v in (None, '') else v}"
    _emit(args, d, text)


def cmd_explain(args):
    from farrier.core.explain import explain, lines
    eng = _engine(args)
    d = explain(eng, _endpoint(eng, args.endpoint))
    _emit(args, d, lambda: lines(d))


def cmd_endpoints_approve(args):
    eng = _engine(args)
    ep = _endpoint(eng, args.endpoint)
    eng.approve(ep["id"], "cli")
    _emit(args, {"ok": True, "endpoint_id": ep["id"]}, lambda: [f"{ep['name']} approved for renewal"])


def cmd_cloud_certs(args):
    from farrier.monitoring.cloud_inventory import inventory
    eng = _engine(args)
    cfg = eng.settings.get("cloud_inventory")
    if not cfg:
        sys.exit('farrier cloud-certs: add "cloud_inventory" to settings.json (aws_regions, aws_accounts, azure_vaults, gcp_projects)')
    out = inventory(cfg)
    _emit(args, out, lambda: [f"{(c['not_after'] or '?')[:10]:<11}{c['source']:<24}{c['location']:<16}"
                              f"{'in use  ' if c['in_use'] else '        '}{c['name']}" for c in out["certificates"]]
          + [f"error: {e['source']} {e['location']}: {e['error']}" for e in out["errors"]])
    if out["errors"]:
        sys.exit(1)


def cmd_ct(args):
    from farrier.core.ct import ct_names
    try:
        rows = ct_names(args.domain)
    except (ValueError, RuntimeError) as e:
        sys.exit(f"farrier ct: {e}")
    hosts = [r["name"] for r in rows if not r["wildcard"]]
    _emit(args, rows, lambda: [f"{(r['not_after'] or '')[:10]:<11}{r['name']:<50}{r['issuer'] or ''}"[:160]
                               for r in rows] + ["", f"{len(hosts)} names; scan them with: farrier scan "
                                                    + " ".join(hosts[:5]) + (" ..." if len(hosts) > 5 else "")])


def cmd_replace(args):
    from farrier.core.replace import replace, select
    eng = _engine(args)
    f = {k: v for k, v in {"issuer": args.issuer, "ca": args.ca, "key_type": args.key_type, "project": args.project,
                           "tag": args.tag, "endpoint_ids": args.endpoint or None}.items() if v}
    try:
        if args.dry_run:
            hits = select(eng, f)
            return _emit(args, hits, lambda: [f"{e['name']:<40}{e['cert_issuer'] or ''}" for e in hits]
                         + [f"{len(hits)} endpoints would be replaced"])
        out = replace(eng, f, args.reason, args.revoke, "cli")
    except ValueError as e:
        sys.exit(f"farrier replace: {e}")
    eng.tick(scan=False)   # start them now
    _emit(args, out, lambda: [f"renewal {r['renewal_id']:<6}{r['name']}" for r in out["renewals"]]
          + [f"skipped {s['name']}: {s['why']}" for s in out["skipped"]]
          + (["old certificates are revoked once nothing serves them"] if args.revoke else []))


def cmd_audit(args):
    from farrier.monitoring import audit
    eng = _engine(args)
    if args.audit_cmd == "export":
        audit.seal(eng.store, limit=10**9)
        data = audit.export(eng.store)
        (Path(args.output).write_bytes(data) if args.output else sys.stdout.buffer.write(data))
        return
    if args.audit_cmd == "check":
        res = audit.check_export(eng.store, Path(args.file).read_bytes())
    else:
        res = audit.verify(eng.store)
    _emit(args, res, lambda: [("intact" if res["ok"] else f"BROKEN at event {res['first_bad_id']}")
                              + (f": {res.get('sealed', res.get('rows'))} events, head {res.get('head')}" if res["ok"] else "")])
    if not res["ok"]:
        sys.exit(1)


def cmd_report(args):
    from farrier.monitoring.audit import compliance
    rep = compliance(_engine(args))

    def text():
        yield f"compliance report, {rep['generated_at']} (public maximum today: {rep['max_public_lifetime_days']} days)"
        for name, p in rep["projects"].items():
            yield (f"{name:<20}{p['endpoints']:>5} endpoints  {p['automated_pct']:>5}% automated  "
                   f"{p.get('expired', 0)} expired  {p.get('expiring_30d', 0)} within 30d  "
                   f"{p.get('failed_renewals_30d', 0)} failed (30d)  {p.get('longer_than_public_maximum', 0)} too long")
        a = rep["audit"]
        yield f"audit log: {'intact' if a['ok'] else 'BROKEN at event ' + str(a['first_bad_id'])}, {a['sealed']} sealed"
    _emit(args, rep, text)


def cmd_runner(args):
    if args.runner_cmd == "start":
        from farrier.runner import run
        token = os.environ.get("FARRIER_RUNNER_TOKEN") or (Path(args.token_file).read_text().strip()
                                                            if args.token_file else "")
        if not token:
            sys.exit("farrier runner: set FARRIER_RUNNER_TOKEN or --token-file (create one with `farrier runner token`)")
        verify = args.ca or not args.insecure
        print(f"farrier runner polling {args.url} every {args.interval:g}s", flush=True)
        run(args.url, token, once=args.once, interval=args.interval, verify_tls=verify,
            log=lambda *a, **k: print(*a, **k, flush=True))
        return
    eng = _engine(args)
    if args.runner_cmd == "token":
        try:
            token = eng.runners.issue_token(args.group)
        except ValueError as e:
            sys.exit(f"farrier runner: {e}")
        eng.store.log(f"runner token for group {args.group} created by cli")
        return _emit(args, {"group": args.group, "token": token}, lambda: [
            token, "", "Shown once. On the runner host:",
            "  FARRIER_RUNNER_TOKEN=<that token> farrier runner start --url https://<engine address>",
            f'Then set "runner": "{args.group}" in the connector_config of the endpoints it should reach.'])
    rows = eng.runners.groups()
    _emit(args, rows, lambda: [f"{g['group']:<24}{g['endpoints']:>4} endpoints  {g['pending_jobs']:>3} pending  "
                               f"last seen {g['last_seen'] or 'never'}" + ("" if g["token"] else "  (no token)")
                               for g in rows] or ["(no runner groups)"])


def cmd_acme_server(args):
    """Farrier's own ACME server: EAB keys for ACME clients, and what they were issued."""
    from farrier.core.acme_server import AcmeServer
    eng = _engine(args)
    acme = AcmeServer(eng)
    if args.acme_what == "certs":
        rows = acme.certificates()
        return _emit(args, rows, lambda: [f"{r['profile']:<14}{(r['not_after'] or '')[:10]:<12}"
                                          f"{'REVOKED ' if r['revoked_at'] else ''}{', '.join(r['identifiers'])}  "
                                          f"(account {r['account_id']}, {r['eab_kid']})" for r in rows]
                     or ["(no certificates issued over ACME)"])
    if args.eab_verb == "create":
        try:
            key = acme.create_eab(args.profile, args.names.split(",") if args.names else [])
        except ValueError as e:
            sys.exit(f"farrier acme-server: {e}")
        eng.store.log(f"acme {args.profile}: EAB key {key['kid']} created by cli"
                      + (f" for {args.names}" if args.names else ""))
        return _emit(args, key, lambda: [
            f"key id:    {key['kid']}", f"hmac key:  {key['hmac_key']}", "",
            "Shown once. Registers one ACME account; the directory is",
            f"  https://<engine address>/acme/{args.profile}/directory",
            f"e.g. certbot --server <directory> --eab-kid {key['kid']} --eab-hmac-key <hmac key> ..."])
    if args.eab_verb == "delete":
        if not acme.delete_eab(args.kid):
            sys.exit(f"farrier acme-server: no EAB key {args.kid}")
        eng.store.log(f"acme: EAB key {args.kid} deleted by cli; its account is revoked")
        return _emit(args, {"ok": True}, lambda: [f"deleted {args.kid}; the account it registered is revoked"])
    rows = acme.eab_keys()
    _emit(args, rows, lambda: [f"{r['kid']:<22}{r['profile']:<14}"
                               f"{'account ' + str(r['account_id']) if r['account_id'] else 'unused':<14}"
                               f"{', '.join(r['names']) or '(profile names)'}" for r in rows] or ["(no EAB keys)"])


def cmd_acm(args):
    """AWS Certificate Manager managed ACME: endpoints, domain prevalidation, External Account Bindings."""
    from farrier.security.cloud_auth.http import CloudError
    try:
        _acm(args)
    except (CloudError, RuntimeError, ValueError) as e:   # AWS refusals and config errors: one line, no traceback
        sys.exit(f"farrier acm: {e}")


def _acm(args):
    from farrier.issuers.aws_acm import KEY_ALGORITHMS, Acm, region_of, wait_until
    from farrier.security.cloud_auth.aws import region_for
    arn = getattr(args, "arn", None)
    acm = Acm(region_of(arn) if arn else region_for("--region", args.region))
    what, verb = args.acm_what, args.acm_verb
    if (what, verb) == ("endpoint", "create"):
        kinds = args.key_types.split(",")
        if set(kinds) - set(KEY_ALGORITHMS):
            sys.exit(f"--key-types: choose from {', '.join(KEY_ALGORITHMS)}")
        new = acm.create_endpoint(kinds, args.contact_required)
        e = wait_until(lambda: acm.describe_endpoint(new)) if args.wait else acm.describe_endpoint(new)
        return _emit(args, e, lambda: [f"endpoint:  {e['AcmeEndpointArn']}", f"status:    {e.get('Status')}",
                                       f"directory: {e.get('EndpointUrl') or '(once ACTIVE)'}",
                                       f"next:      farrier acm domain add {new} <domain> [--hosted-zone-id Z...]"])
    if (what, verb) == ("domain", "add"):
        new = acm.add_domain(arn, args.domain, args.hosted_zone_id, not args.no_subdomains, args.wildcards)
        d = (wait_until(lambda: acm.describe_domain(new), timeout=args.timeout) if args.wait
             else acm.describe_domain(new))
        return _emit(args, d, lambda: _acm_domain_lines(d))
    if (what, verb) == ("eab", "create"):
        b = acm.create_eab(arn, args.role_arn, args.expires_days)
        entry = {"acm": {"preset": "aws-acm", "acm_eab_arn": b["AcmeExternalAccountBindingArn"]}}
        return _emit(args, b, lambda: [f"binding:  {b['AcmeExternalAccountBindingArn']}",
                                       f"expires:  {b.get('ExpiresAt') or 'never'}",
                                       "issuers.json entry (the engine reads the key from ACM with its IAM role):",
                                       "  " + json.dumps(entry),
                                       "outside AWS: `farrier acm eab credentials <binding>`, store both as secrets"])
    if (what, verb) == ("eab", "credentials"):
        kid, mac = acm.eab_credentials(arn)
        return _emit(args, {"KeyId": kid, "MacKey": mac}, lambda: [f"key id:   {kid}", f"hmac key: {mac}"])
    if verb in ("delete", "revoke"):
        getattr(acm, f"{verb}_{what}")(arn)
        return _emit(args, {"ok": True, "arn": arn}, lambda: [f"{what} {verb}d: {arn}"])
    if verb == "show":
        obj = getattr(acm, f"describe_{what}")(arn)
        return _emit(args, obj, lambda: _acm_domain_lines(obj) if what == "domain"
                     else [f"{k + ':':<24}{v}" for k, v in obj.items()])
    rows = acm.list_endpoints() if what == "endpoint" else getattr(acm, f"list_{what}s")(arn)
    key = {"endpoint": "AcmeEndpointArn", "domain": "DomainName", "eab": "AcmeExternalAccountBindingArn"}[what]
    _emit(args, rows, lambda: [f"{r.get('Status') or ('revoked' if r.get('RevokedAt') else 'active'):<11}{r[key]}"
                               + (f"  {r['EndpointUrl']}" if r.get("EndpointUrl") else "") for r in rows]
          or ["(none)"])


def _acm_domain_lines(d: dict):
    yield f"domain:     {d.get('DomainName')}"
    yield f"validation: {d.get('AcmeDomainValidationArn')}"
    yield f"status:     {d.get('Status')}" + (f" ({d['FailureDetails']})" if d.get("FailureDetails") else "")
    dns = (d.get("PrevalidationDetails") or {}).get("DnsPrevalidation") or {}
    if dns.get("HostedZoneId"):
        yield f"route 53:   ACM writes the CNAME in hosted zone {dns['HostedZoneId']}"
    elif dns.get("ResourceRecord"):
        rr = dns["ResourceRecord"]
        yield f"create:     {rr['Name']} CNAME {rr['Value']}"
        yield "            keep this record: it authorizes every future issuance (ACM checks for up to 72 hours)"


def main(argv=None):
    from farrier import __version__
    p = argparse.ArgumentParser(prog="farrier", description="Agentless machine identity automation: TLS "
                                "certificates, SSH keys, cryptographic discovery and PQC readiness.")
    p.add_argument("--version", action="version", version=f"farrier {__version__}")
    p.add_argument("--data", default=os.environ.get("FARRIER_DATA", "./farrier-data"),
                   help="data directory (default: $FARRIER_DATA, else ./farrier-data)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the engine API (OpenAPI at /docs) and the background renewal loop; "
                       "the dashboard is the separate web app")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8740)
    s.add_argument("--tick", type=float, default=300, help="seconds between scan/plan/advance cycles")
    s.add_argument("--grace", type=float, default=float(os.environ.get("FARRIER_SHUTDOWN_GRACE", "20")),
                   help="seconds to drain requests on SIGTERM; the running tick gets as long again")
    s.set_defaults(fn=cmd_serve)

    s = sub.add_parser("db", help="database maintenance")
    dbsub = s.add_subparsers(dest="db_cmd", required=True)
    m = dbsub.add_parser("migrate", help="copy every table from the current database to a new one")
    m.add_argument("--to", required=True, help="destination URL, e.g. postgresql://farrier@db/farrier"
                   "?sslmode=verify-full (password via FARRIER_DATABASE_PASSWORD or env:/file: reference)")
    m.add_argument("--from", dest="source", default=None,
                   help="source URL (default: FARRIER_DATABASE_URL, else the SQLite file in --data)")
    m.set_defaults(fn=cmd_db_migrate)

    s = sub.add_parser("backup", help="export the database (JSON lines, sealed values stay sealed) to object storage")
    s.add_argument("--to", required=True, help="storage URL: s3://bucket/prefix, gs://bucket/prefix, "
                   "azblob://account/container/prefix or file:///path")
    s.set_defaults(fn=cmd_backup)

    s = sub.add_parser("restore", help="load a backup into an empty database")
    s.add_argument("--from", dest="source", required=True, help="URL of the backup object written by farrier backup")
    s.add_argument("--to", default=None, help="destination database URL (default: FARRIER_DATABASE_URL, else the "
                   "SQLite file in --data); must be empty")
    s.add_argument("--allow-unsigned", action="store_true",
                   help="restore a backup without a valid signature (made before signing, or by another master "
                   "key); rows with connector commands still need FARRIER_ALLOW_API_COMMANDS=1")
    s.set_defaults(fn=cmd_restore)

    s = sub.add_parser("demo", help="serve a simulated estate of real TLS endpoints and run the API against it")
    s.add_argument("--port", type=int, default=8740)
    s.add_argument("--tick", type=float, default=20)
    s.add_argument("--simulate-date", help="issue certs as if on this date, e.g. 2029-03-15 for 47-day life")
    s.add_argument("--host", default="127.0.0.1", help="API bind address (non-loopback needs FARRIER_API_TOKEN)")
    s.set_defaults(fn=cmd_demo)

    s = sub.add_parser("scan", help="handshake with TLS targets and report the certificates they serve")
    s.add_argument("targets", nargs="+", help="host[:port], 10.0.0.0/24:443|8443, sni@ip:port")
    s.add_argument("--register", action="store_true", help="add unknown endpoints to the inventory")
    s.add_argument("--timeout", type=float, default=3.0)
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("tick", help="run one scan/plan/advance cycle on the data directory and print the result")
    s.set_defaults(fn=cmd_tick)

    s = sub.add_parser("import", help="import endpoints from a JSON inventory file")
    s.add_argument("file")
    s.set_defaults(fn=cmd_import)

    s = sub.add_parser("forecast", help="renewal workload under the CA/B Forum schedule")
    s.add_argument("--certs", type=int, default=1000)
    s.add_argument("--manual", type=float, default=0.4, help="fraction needing a human (0-1)")
    s.add_argument("--minutes", type=float, default=45, help="hands-on minutes per manual renewal")
    s.add_argument("--lead", type=int, default=0, help="change lead time in days")
    s.set_defaults(fn=cmd_forecast)

    s = sub.add_parser("mcp", help="run the Model Context Protocol server on stdio (for AI agents)")
    s.set_defaults(fn=cmd_mcp)

    s = sub.add_parser("version", help="print the version")
    s.set_defaults(fn=cmd_version)

    def js(x):
        x.add_argument("--json", action="store_true", help="machine-readable JSON output")
        return x

    s = sub.add_parser("ssh", help="SSH host discovery and authorized keys")
    ssub = s.add_subparsers(dest="ssh_cmd", required=True)
    x = js(ssub.add_parser("scan", help="probe SSH targets without logging in: banner, host keys, PQC key "
                           "exchange, findings; results are stored"))
    x.add_argument("targets", nargs="+", help="host[:port] or CIDR (default port 22)")
    x.set_defaults(fn=cmd_ssh_scan)
    js(ssub.add_parser("keys", help="list collected authorized keys with their findings")).set_defaults(fn=cmd_ssh_keys)

    s = sub.add_parser("crypto", help="cryptographic discovery and PQC readiness")
    csub = s.add_subparsers(dest="crypto_cmd", required=True)
    x = js(csub.add_parser("scan", help="probe TLS targets: versions, key exchange, PQC status; results are stored"))
    x.add_argument("targets", nargs="+", help="host[:port], 10.0.0.0/24:443|8443, sni@ip:port")
    x.add_argument("--timeout", type=float, default=None, help="seconds per handshake (default: scan_timeout setting)")
    x.set_defaults(fn=cmd_crypto_scan)
    js(csub.add_parser("summary", help="stored assets by PQC status, key algorithm and weak-crypto flag")
       ).set_defaults(fn=cmd_crypto_summary)
    x = csub.add_parser("cbom", help="CycloneDX 1.6 cryptography bill of materials of every stored asset (JSON)")
    x.add_argument("-o", "--output", help="write to this file instead of stdout")
    x.set_defaults(fn=cmd_crypto_cbom)

    s = sub.add_parser("certs", help="certificates in the inventory")
    csub = s.add_subparsers(dest="certs_cmd", required=True)
    x = js(csub.add_parser("show", help="certificate details of an endpoint: subject, SANs, key, chain, renewals "
                           f"(exit {NOT_FOUND} if there is no such endpoint)"))
    x.add_argument("endpoint", help="endpoint name or id")
    x.set_defaults(fn=cmd_certs_show)

    x = js(sub.add_parser("explain", help="why the next renewal is when it is: lifetime maths, ARI, change window, "
                          "daily cap, backoff, approval, issuance policy, runner group, last failure with its reason "
                          f"code (exit {NOT_FOUND} if there is no such endpoint)"))
    x.add_argument("endpoint", help="endpoint name or id")
    x.set_defaults(fn=cmd_explain)

    s = sub.add_parser("endpoints", help="inventory endpoints")
    esub = s.add_subparsers(dest="endpoints_cmd", required=True)
    x = js(esub.add_parser("approve", help="let a discovered endpoint be renewed (logged with actor cli)"))
    x.add_argument("endpoint", help="endpoint name or id")
    x.set_defaults(fn=cmd_endpoints_approve)

    x = js(sub.add_parser("replace", help="incident drill: renew every matching endpoint now, optionally revoking "
                          "the old certificates once nothing serves them"))
    x.add_argument("--issuer", help="issuers.json name")
    x.add_argument("--ca", help="text in the served certificate's issuer, e.g. R10 or Entrust")
    x.add_argument("--key-type", help="e.g. rsa2048")
    x.add_argument("--project")
    x.add_argument("--tag")
    x.add_argument("--endpoint", type=int, action="append", help="endpoint id (repeatable)")
    x.add_argument("--reason", default="superseded", help="keyCompromise, cACompromise, superseded (default), ...")
    x.add_argument("--revoke", action="store_true", help="revoke each old certificate once nothing serves it")
    x.add_argument("--dry-run", action="store_true", help="list what would be replaced")
    x.set_defaults(fn=cmd_replace)

    s = sub.add_parser("audit", help="the tamper-evident activity log: verify, export, check an export")
    asub2 = s.add_subparsers(dest="audit_cmd", required=True)
    js(asub2.add_parser("verify", help="recompute the hash chain (exit 1 if broken)")).set_defaults(fn=cmd_audit)
    x = asub2.add_parser("export", help="JSON lines of every event, ending with the signed chain head")
    x.add_argument("-o", "--output", help="write to this file instead of stdout")
    x.set_defaults(fn=cmd_audit)
    x = js(asub2.add_parser("check", help="verify an export file: every link and the signature"))
    x.add_argument("file")
    x.set_defaults(fn=cmd_audit)
    js(sub.add_parser("report", help="compliance report: coverage, expiry risk, failures, 47-day readiness, audit"
                      )).set_defaults(fn=cmd_report)

    s = sub.add_parser("runner", help="remote runners: Farrier's hands inside segmented networks (outbound HTTPS only)")
    rsub = s.add_subparsers(dest="runner_cmd", required=True)
    x = rsub.add_parser("start", help="run a runner: claim this group's jobs from the engine and run them here")
    x.add_argument("--url", required=True, help="the engine's address as this host reaches it, e.g. https://farrier-gw")
    x.add_argument("--token-file", help="file holding the group token (default: $FARRIER_RUNNER_TOKEN)")
    x.add_argument("--interval", type=float, default=5, help="seconds between polls when idle (default 5)")
    x.add_argument("--ca", help="CA bundle for the engine's TLS certificate")
    x.add_argument("--insecure", action="store_true", help="don't verify the engine's TLS certificate (labs only)")
    x.add_argument("--once", action="store_true", help="poll once, run what is there, exit")
    x.set_defaults(fn=cmd_runner)
    x = js(rsub.add_parser("token", help="create or replace a runner group's token (on the engine host)"))
    x.add_argument("group", help="e.g. dmz-frankfurt")
    x.set_defaults(fn=cmd_runner)
    js(rsub.add_parser("list", help="runner groups: endpoints, pending jobs, last seen")).set_defaults(fn=cmd_runner)

    js(sub.add_parser("cloud-certs", help="certificates in AWS ACM, Azure Key Vault and Google Certificate Manager "
                      "(settings.json cloud_inventory)")).set_defaults(fn=cmd_cloud_certs)

    x = js(sub.add_parser("ct", help="names with a valid public certificate under a domain, from Certificate "
                          "Transparency logs (crt.sh)"))
    x.add_argument("domain", help="e.g. example.com (covers every name below it)")
    x.set_defaults(fn=cmd_ct)

    s = sub.add_parser("acme-server", help="Farrier's ACME server (settings.json acme_server): EAB keys and "
                       "the certificates ACME clients got")
    asub = s.add_subparsers(dest="acme_what", required=True)
    js(asub.add_parser("certs", help="certificates issued over ACME: profile, names, account, expiry")
       ).set_defaults(fn=cmd_acme_server)
    b = asub.add_parser("eab", help="External Account Binding keys: each registers one ACME account")
    vsub = b.add_subparsers(dest="eab_verb", required=True)
    x = js(vsub.add_parser("create", help="a new key for a profile (the HMAC key is shown once)"))
    x.add_argument("profile", help="an acme_server profile in settings.json")
    x.add_argument("--names", help="comma-separated name patterns this key may order, within the profile's")
    js(vsub.add_parser("list", help="keys, their profile and names, and whether they registered an account"))
    js(vsub.add_parser("delete", help="delete a key and revoke the account it registered")).add_argument("kid")
    b.set_defaults(fn=cmd_acme_server)

    s = sub.add_parser("acm", help="AWS Certificate Manager managed ACME: endpoints, domains, EAB credentials")
    s.add_argument("--region", default=None, help="AWS region for create/list (default: $AWS_REGION); commands "
                   "that take an ARN use its region")
    asub = s.add_subparsers(dest="acm_what", required=True)
    e = asub.add_parser("endpoint", help="ACME endpoints (each one a directory URL and an authorization boundary)")
    vsub = e.add_subparsers(dest="acm_verb", required=True)
    x = js(vsub.add_parser("create", help="create a PRE_APPROVED endpoint for public certificates"))
    x.add_argument("--key-types", default="ec256", help="comma-separated: ec256, ec384, rsa2048 (default ec256)")
    x.add_argument("--contact-required", action="store_true", help="ACME accounts must give a contact email")
    x.add_argument("--wait", action="store_true", help="wait until ACTIVE and print the directory URL")
    js(vsub.add_parser("list", help="endpoints in the region"))
    for verb, h in (("show", "status and directory URL"),
                    ("delete", "delete with its domains and bindings (issued certificates stay valid)")):
        js(vsub.add_parser(verb, help=h)).add_argument("arn", help="endpoint ARN")
    d = asub.add_parser("domain", help="domain prevalidation: the names an endpoint may issue for")
    vsub = d.add_subparsers(dest="acm_verb", required=True)
    x = js(vsub.add_parser("add", help="allow a domain; ACM proves control through one CNAME"))
    x.add_argument("arn", help="endpoint ARN")
    x.add_argument("domain", help="e.g. example.com")
    x.add_argument("--hosted-zone-id", help="Route 53 hosted zone: ACM creates the CNAME itself")
    x.add_argument("--no-subdomains", action="store_true", help="only the exact domain, not names below it")
    x.add_argument("--wildcards", action="store_true", help="also allow *.domain certificates")
    x.add_argument("--wait", action="store_true", help="wait until VALID (or INVALID)")
    x.add_argument("--timeout", type=float, default=1800, help="seconds --wait waits (default 1800)")
    js(vsub.add_parser("list", help="domains of an endpoint")).add_argument("arn", help="endpoint ARN")
    for verb, h in (("show", "status and the CNAME to create"), ("delete", "stop issuing for this domain")):
        js(vsub.add_parser(verb, help=h)).add_argument("arn", help="domain validation ARN")
    b = asub.add_parser("eab", help="External Account Bindings: what authorizes an ACME client")
    vsub = b.add_subparsers(dest="acm_verb", required=True)
    x = js(vsub.add_parser("create", help="create a binding tied to an IAM issuance role"))
    x.add_argument("arn", help="endpoint ARN")
    x.add_argument("--role-arn", required=True, help="IAM role ACM assumes to issue (acm:RequestCertificate)")
    x.add_argument("--expires-days", type=int, help="stop registering new accounts after this many days")
    js(vsub.add_parser("list", help="bindings of an endpoint")).add_argument("arn", help="endpoint ARN")
    for verb, h in (("credentials", "print the key id and HMAC key, for ACME clients other than Farrier"),
                    ("revoke", "no new accounts with this binding (existing accounts keep working)"),
                    ("delete", "remove the binding for good")):
        js(vsub.add_parser(verb, help=h)).add_argument("arn", help="binding ARN")
    for parser in (e, d, b):
        parser.set_defaults(fn=cmd_acm)

    def describe(parser):   # `farrier <cmd> --help` opens with the same one-liner the command list shows
        for action in parser._subparsers._group_actions if parser._subparsers else ():
            for choice in action._choices_actions:
                child = action.choices[choice.dest]
                child.description = child.description or choice.help
                describe(child)
    describe(p)

    args = p.parse_args(argv)
    if args.cmd == "demo" and "--data" not in (argv if argv is not None else sys.argv)             and not os.environ.get("FARRIER_DATA"):
        args.data = "./farrier-demo"
    args.fn(args)


if __name__ == "__main__":
    main()
