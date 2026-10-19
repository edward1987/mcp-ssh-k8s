"""Dump Termius' local IndexedDB (read-only copy) as JSON on stdout.

Needs:  pip install git+https://github.com/cclgroupltd/ccl_chromium_reader
Secrets stay encrypted here: decryption happens in the Node server with the key from Windows Credential Manager.
"""
import base64, datetime, json, os, shutil, sys, tempfile

from ccl_chromium_reader import ccl_chromium_indexeddb as idb

STORES = {"hosts", "groups", "ssh_configs", "ssh_config_identities", "ssh_identities", "ssh_keys", "ssh_certificates", "tags", "tag_hosts", "keys", "multi_keys"}


def jsonable(v):
    if isinstance(v, (bytes, bytearray)):
        return base64.b64encode(bytes(v)).decode()
    if isinstance(v, (datetime.datetime, datetime.date)):
        return v.isoformat()
    if isinstance(v, dict):
        return {str(k): jsonable(x) for k, x in v.items()}
    if isinstance(v, (list, tuple, set)):
        return [jsonable(x) for x in v]
    if isinstance(v, (str, int, float, bool)) or v is None:
        return v
    return str(v)


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.environ["APPDATA"], "Termius", "IndexedDB", "file__0.indexeddb.leveldb")
    tmp = tempfile.mkdtemp()
    try:
        dst = os.path.join(tmp, "db")
        shutil.copytree(src, dst, ignore=shutil.ignore_patterns("LOCK"))  # Termius keeps the live DB locked
        w = idb.WrappedIndexDB(dst)
        out = {}
        for dbid in w.database_ids:
            if dbid.name not in STORES:
                continue
            db = w[dbid.dbid_no]
            recs = []
            for sname in db.object_store_names:
                for rec in db[sname].iterate_records():
                    if isinstance(rec.value, dict):
                        recs.append(jsonable(rec.value))
            out[dbid.name] = recs
        json.dump(out, sys.stdout)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


main()
