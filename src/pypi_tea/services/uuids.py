import uuid

PYPOT_NAMESPACE = uuid.UUID("d4f1a3b2-7e6c-4a8f-9b0d-2c5e8f1a3b7d")


def product_uuid(name: str) -> str:
    return str(uuid.uuid5(PYPOT_NAMESPACE, f"pkg:pypi/{name}"))


def product_release_uuid(name: str, version: str) -> str:
    return str(uuid.uuid5(PYPOT_NAMESPACE, f"pkg:pypi/{name}@{version}"))


def component_uuid(filename: str) -> str:
    return str(uuid.uuid5(PYPOT_NAMESPACE, f"wheel:{filename}"))


def component_release_uuid(url: str) -> str:
    return str(uuid.uuid5(PYPOT_NAMESPACE, url))


def artifact_uuid(wheel_url: str, sbom_path: str) -> str:
    return str(uuid.uuid5(PYPOT_NAMESPACE, f"sbom:{wheel_url}:{sbom_path}"))
