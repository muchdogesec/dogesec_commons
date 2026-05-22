ATTACK_TYPES = [
    "attack-pattern",
    "campaign",
    "course-of-action",
    "identity",
    "intrusion-set",
    "malware",
    "marking-definition",
    "tool",
    "x-mitre-data-component",
    "x-mitre-data-source",
    "x-mitre-matrix",
    "x-mitre-tactic",
    'x-mitre-asset',
    "x-mitre-detection-strategy",
    "x-mitre-analytic",
]
ATLAS_TYPES = [
  "attack-pattern",
  "course-of-action",
#   "identity",
#   "marking-definition",
  "x-mitre-collection",
  "x-mitre-matrix",
  "x-mitre-tactic"
]


KNOWLEDGEBASE_TYPE_MAPPING = {
    "cve": {
        "host": "vulmatch",
        "stix_type": "vulnerability",
        "source_name": None,
        "endpoint": "v1/cve/objects/?stix_id={values}",
    },
    "cwe": {
        "stix_type": "weakness",
        "source_name": None,
        "endpoint": "v1/cwe/objects/?id={values}",
    },
    "location": {
        "stix_type": "location",
        "source_name": None,
        "endpoint": "v1/location/objects/?id={values}",
    },
    "capec": {
        "stix_type": ATLAS_TYPES,
        "source_name": "capec",
        "endpoint": "v1/capec/objects/?id={values}",
    },
    "atlas": {
        "stix_type": ATLAS_TYPES,
        "source_name": "mitre-atlas",
        "endpoint": "v1/atlas/objects/?id={values}",
    },
    "disarm": {
        "stix_type": ATLAS_TYPES,
        "source_name": "DISARM",
        "endpoint": "v1/disarm/objects/?id={values}",
    },
    "sector": {
        "stix_type": "identity",
        "source_name": "sector2stix",
        "endpoint": "v1/sectors/objects/?id={values}",
    },
    "enterprise-attack": {
        "stix_type": ATTACK_TYPES,
        "source_name": None,
        "mitre_domain": "enterprise-attack",
        "endpoint": "v1/attack-enterprise/objects/?id={values}",
    },
    "mobile-attack": {
        "stix_type": ATTACK_TYPES,
        "source_name": None,
        "mitre_domain": "mobile-attack",
        "endpoint": "v1/attack-mobile/objects/?id={values}",
    },
    "ics-attack": {
        "stix_type": ATTACK_TYPES,
        "source_name": None,
        "mitre_domain": "ics-attack",
        "endpoint": "v1/attack-ics/objects/?id={values}",
    },
}

