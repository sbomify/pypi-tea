"""Seed a SQLite store with N synthetic releases, S of them with SBOMs (3 wheels each)."""

import json
import sys
import time

from pypi_tea import db, store
from pypi_tea.models import ReleaseRecord, SbomRecord, WheelRecord
from pypi_tea.services.uuids import artifact_uuid

ROOT = "http://127.0.0.1:9100"
SBOM = json.dumps(
    {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [{"type": "library", "name": f"dep{i}", "version": "1.0"} for i in range(50)],
    }
)


def main(path: str, total: int, with_sbom: int) -> None:
    db.init_schema(path)
    conn = db.connect(path)
    t0 = time.time()
    for i in range(total):
        name, version = f"pkg{i}", "1.0.0"
        wheels = []
        for w in range(3):
            fn = f"{name}-{version}-cp312-cp312-manylinux_2_17_x86_64_{w}.whl"
            url = f"{ROOT}/files/{fn}"
            sboms = []
            if i < with_sbom:
                p = f"{name}-{version}.dist-info/sboms/{name}.cdx.json"
                sboms.append(
                    SbomRecord(
                        uuid=artifact_uuid(url, p),
                        path=p,
                        media_type="application/vnd.cyclonedx+json",
                        sha256="0" * 64,
                        format="CycloneDX/1.6",
                        valid=True,
                        content=SBOM,
                    )
                )
            wheels.append(
                WheelRecord(
                    url=url,
                    filename=fn,
                    digests={"sha256": "0" * 64},
                    size=1000,
                    sboms=sboms,
                    attestation={"status": "not_available"},
                )
            )
        store.save_release(
            conn,
            ReleaseRecord(
                name=name,
                version=version,
                created="2025-01-01T00:00:00Z",
                info={"summary": f"{name} summary", "license": "MIT"},
                wheels=wheels,
            ),
        )
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.execute("ANALYZE")
    print(f"seeded {total} releases in {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))
