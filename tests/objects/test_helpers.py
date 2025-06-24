import random
import time
import pytest
from unittest.mock import MagicMock, patch
from rest_framework.test import APIRequestFactory
from dogesec_commons.objects import conf
from dogesec_commons.objects.helpers import positive_int, ArangoDBHelper
from tests.objects.data import SRO_DATA
from .utils import make_s2a_uploads, request_from_queries
from rest_framework.exceptions import NotFound


def test_get_objects_uses_view_and_has_no_duplicates(subtests):
    helper = ArangoDBHelper(conf.ARANGODB_DATABASE_VIEW, None)

    def test_no_duplicate(response_data, expected_ids):
        objects = response_data["objects"]
        object_ids = {obj["id"] for obj in objects}
        assert (
            len(object_ids) == response_data["page_results_count"]
        ), "duplicates in response"
        assert object_ids == expected_ids, object_ids

    with make_s2a_uploads(
        [
            (
                "collection1",
                [
                    {
                        "type": "ipv4-addr",
                        "spec_version": "2.1",
                        "id": "ipv4-addr--cbd67181-b9f8-595b-8bc3-3971e34fa1cc",
                        "value": "1.1.1.1",
                    },
                    {
                        "type": "not-an-sco",
                        "spec_version": "2.1",
                        "id": "not-an-sco--cbd67181-b9f8-595b-8bc3-3971e34fa1cc",
                        "value": "1.1.1.1",
                    },
                    {
                        "type": "marking-definition",
                        "id": "marking-definition--cbd67181-b9f8-595b-8bc3-3971e34fa1cc",
                    },  # SMO
                    {
                        "type": "extension-definition",
                        "id": "extension-definition--cbd67181-b9f8-595b-8bc3-3971e34fa1cc",
                    },  # SMO
                    {
                        "type": "network-traffic",
                        "spec_version": "2.1",
                        "id": "network-traffic--4f2724da-746b-5e13-b6e2-30693a9d6977",
                        "dst_ref": "ipv4-addr--cbd67181-b9f8-595b-8bc3-3971e34fa1cc",
                        "dst_port": 80,
                        "protocols": ["ipv4"],
                    },
                    {
                        "type": "relationship",
                        "id": "relationship--9cf0369a-8646-4979-ae2c-ab0d3c95bfad",
                        "source_ref": "some-source--1",
                        "target_ref": "some-target--1",
                    },  # SRO1
                    {
                        "type": "relationship",
                        "id": "relationship--2c8df0f5-1a2b-4b1b-9f13-21a2767c8f0d",
                        "source_ref": "some-source--1",
                        "target_ref": "some-target--1",
                    },  # SRO3
                    {
                        "type": "vulnerability",
                        "id": "vulnerability--1162f86e-c825-4b20-a69e-ea8a6d9d3948",
                    },  # SDO1
                    {
                        "type": "indicator",
                        "id": "indicator--d28eedd5-8066-4b4a-a6e8-a31795403f97",
                    },  # SDO2
                ],
            ),
            (
                "collection2",
                [
                    {
                        "type": "ipv4-addr",
                        "spec_version": "2.1",
                        "id": "ipv4-addr--cbd67181-b9f8-595b-8bc3-3971e34fa1cc",
                        "value": "1.1.1.1",
                    },
                    {
                        "type": "ipv4-addr",
                        "spec_version": "2.1",
                        "id": "ipv4-addr--8e594bf5-81f2-5460-9e43-62e6a06794e0",
                        "value": "1.1.1.1/24",
                    },
                    {
                        "type": "marking-definition",
                        "spec_version": "2.1",
                        "id": "marking-definition--cbd67181-b9f8-595b-8bc3-3971e34fa1cc",
                        "value": "1.1.1.1",
                    },  # SMOs
                    {
                        "type": "language-content",
                        "id": "language-content--cbd67181-b9f8-595b-8bc3-3971e34fa1cc",
                    },  # SMO
                    {
                        "type": "relationship",
                        "id": "relationship--9cf0369a-8646-4979-ae2c-ab0d3c95bfad",
                        "source_ref": "some-source--2",
                        "target_ref": "some-target--2",
                    },  # SRO1
                    {
                        "type": "relationship",
                        "id": "relationship--1162f86e-c825-4b20-a69e-ea8a6d9d3948",
                        "source_ref": "some-source--3",
                        "target_ref": "some-target--3",
                    },  # SRO2
                    {
                        "type": "vulnerability",
                        "id": "vulnerability--1162f86e-c825-4b20-a69e-ea8a6d9d3948",
                    },  # SDO1
                    {
                        "type": "weakness",
                        "id": "weakness--cbd67181-b9f8-595b-8bc3-3971e34fa1cc",
                    },  # SDO3
                ],
            ),
        ],
        truncate_collection=True,
    ) as s2a:
        # for filters, expected in subtests_cases:
        with subtests.test("get_scos"):
            response_data = helper.get_scos().data
            test_no_duplicate(
                response_data,
                {
                    "ipv4-addr--cbd67181-b9f8-595b-8bc3-3971e34fa1cc",
                    "ipv4-addr--8e594bf5-81f2-5460-9e43-62e6a06794e0",
                    "network-traffic--4f2724da-746b-5e13-b6e2-30693a9d6977",
                },
            )

        with subtests.test("get_smos"):
            response_data = helper.get_smos().data
            test_no_duplicate(
                response_data,
                {
                    "language-content--cbd67181-b9f8-595b-8bc3-3971e34fa1cc",
                    "marking-definition--cbd67181-b9f8-595b-8bc3-3971e34fa1cc",
                    "extension-definition--cbd67181-b9f8-595b-8bc3-3971e34fa1cc",
                    ## s2a default objects
                    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
                    "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
                    "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
                    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
                    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
                    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                    "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
                    "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
                    "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003",
                    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
                    "marking-definition--72e906ce-ca1b-5d73-adcd-9ea9eb66a1b4",
                },
            )

        with subtests.test("get_sros"):
            helper = ArangoDBHelper(
                helper.collection, request_from_queries(include_embedded_refs="false")
            )
            response_data = helper.get_sros().data
            test_no_duplicate(
                response_data,
                {
                    "relationship--9cf0369a-8646-4979-ae2c-ab0d3c95bfad",
                    "relationship--1162f86e-c825-4b20-a69e-ea8a6d9d3948",
                    "relationship--2c8df0f5-1a2b-4b1b-9f13-21a2767c8f0d",
                },
            )

        with subtests.test("get_sdos"):
            helper = ArangoDBHelper(
                helper.collection, request_from_queries(include_embedded_refs="false")
            )
            response_data = helper.get_sdos().data
            test_no_duplicate(
                response_data,
                {
                    "weakness--cbd67181-b9f8-595b-8bc3-3971e34fa1cc",
                    "indicator--d28eedd5-8066-4b4a-a6e8-a31795403f97",
                    "vulnerability--1162f86e-c825-4b20-a69e-ea8a6d9d3948",
                    ## default identity
                    "identity--72e906ce-ca1b-5d73-adcd-9ea9eb66a1b4",
                },
            )


sco_objects = [
    {"type": "artifact", "payload_bin": "some unrelated content", "id": "artifact-1"},
    {"type": "autonomous-system", "number": "AS12345", "id": "as-1"},
    {
        "type": "bank-account",
        "iban_number": "DE89370400440532013000",
        "id": "bank-acc-1",
    },
    {"type": "bank-card", "number": "4111111111111111", "id": "bank-card-1"},
    {
        "type": "cryptocurrency-transaction",
        "hash": "abcde98765fghij",
        "id": "crypto-tx-1",
    },
    {"type": "cryptocurrency-wallet", "hash": "wallet-hash-xyz789", "id": "wallet-1"},
    {"type": "directory", "path": "/usr/local/bin", "id": "dir-1"},
    {"type": "domain-name", "value": "example.net", "id": "domain-1"},
    {"type": "email-addr", "value": "user@example.com", "id": "email-1"},
    {"type": "email-message", "body": "Nothing relevant here", "id": "email-msg-1"},
    {"type": "file", "name": "report.pdf", "id": "file-1"},
    {"type": "ipv4-addr", "value": "192.168.0.123", "id": "ipv4-1"},
    {"type": "ipv6-addr", "value": "fe80::5678:abcd", "id": "ipv6-1"},
    {"type": "mac-addr", "value": "aa:bb:cc:dd:ee:ff", "id": "mac-1"},
    {"type": "mutex", "value": "Global\\SomeMutex", "id": "mutex-1"},
    {"type": "network-traffic", "protocols": "tcp,udp,icmp", "id": "net-1"},
    {"type": "phone-number", "number": "+1-123-456-7890", "id": "phone-1"},
    {"type": "process", "pid": "12399", "id": "process-1"},
    {"type": "software", "name": "Antivirus", "id": "software-1"},
    {"type": "url", "value": "https://example.com", "id": "url-1"},
    {"type": "user-account", "display_name": "Regular User", "id": "user-1"},
    {"type": "user-agent", "string": "Mozilla/5.0", "id": "agent-1"},
    {
        "type": "windows-registry-key",
        "key": "HKEY_LOCAL_MACHINE\\Software\\Key\\Subkey123",
        "id": "regkey-1",
    },
    {"type": "x509-certificate", "subject": "CN=TrustedCert Authority", "id": "cert-1"},
]

SCO_VALUE_FILTER_TEST_DATA = test_data = [
    pytest.param(
        [
            {
                "type": "artifact",
                "payload_bin": "some static content",
                "id": "artifact-1",
            }
        ],
        "static",
        ["artifact-1"],
        id="match-artifact-on-payload_bin",
    ),
    pytest.param(
        [{"type": "autonomous-system", "number": "AS12345", "id": "as-1"}],
        "123",
        ["as-1"],
        id="match-autonomous-system-on-number",
    ),
    pytest.param(
        [
            {
                "type": "bank-account",
                "iban_number": "DE89370400440532013000",
                "id": "bank-acc-1",
            }
        ],
        "3201",
        ["bank-acc-1"],
        id="match-bank-account-on-iban_number",
    ),
    pytest.param(
        [{"type": "bank-card", "number": "4111111111111111", "id": "bank-card-1"}],
        "1111",
        ["bank-card-1"],
        id="match-bank-card-on-number",
    ),
    pytest.param(
        [
            {
                "type": "cryptocurrency-transaction",
                "hash": "abcde12345fghij",
                "id": "crypto-tx-1",
            }
        ],
        "12345",
        ["crypto-tx-1"],
        id="match-crypto-tx-on-hash",
    ),
    pytest.param(
        [
            {
                "type": "cryptocurrency-wallet",
                "hash": "wallet-hash-xyz789",
                "id": "wallet-1",
            }
        ],
        "xyz",
        ["wallet-1"],
        id="match-crypto-wallet-on-hash",
    ),
    pytest.param(
        [{"type": "directory", "path": "/usr/local/static/bin", "id": "dir-1"}],
        "static",
        ["dir-1"],
        id="match-directory-on-path",
    ),
    pytest.param(
        [{"type": "domain-name", "value": "malicious-static.net", "id": "domain-1"}],
        "static",
        ["domain-1"],
        id="match-domain-name-on-value",
    ),
    pytest.param(
        [{"type": "email-addr", "value": "attacker@static.com", "id": "email-1"}],
        "static",
        ["email-1"],
        id="match-email-addr-on-value",
    ),
    pytest.param(
        [
            {
                "type": "email-message",
                "body": "This message contains static content.",
                "id": "email-msg-1",
            }
        ],
        "static",
        ["email-msg-1"],
        id="match-email-message-on-body",
    ),
    pytest.param(
        [{"type": "file", "name": "static.exe", "id": "file-1"}],
        "static",
        ["file-1"],
        id="match-file-on-name",
    ),
    pytest.param(
        [{"type": "ipv4-addr", "value": "192.168.1.123", "id": "ipv4-1"}],
        "123",
        ["ipv4-1"],
        id="match-ipv4-addr-on-value",
    ),
    pytest.param(
        [{"type": "ipv6-addr", "value": "fe80::1234:abcd", "id": "ipv6-1"}],
        "1234",
        ["ipv6-1"],
        id="match-ipv6-addr-on-value",
    ),
    pytest.param(
        [{"type": "mac-addr", "value": "aa:bb:cc:dd:ee:ff", "id": "mac-1"}],
        "dd:ee",
        ["mac-1"],
        id="match-mac-addr-on-value",
    ),
    pytest.param(
        [{"type": "mutex", "value": "Global\\StaticMutexName", "id": "mutex-1"}],
        "static",
        ["mutex-1"],
        id="match-mutex-on-value",
    ),
    pytest.param(
        [{"type": "network-traffic", "protocols": "tcp,udp,icmp", "id": "net-1"}],
        "icmp",
        ["net-1"],
        id="match-network-traffic-on-protocols",
    ),
    pytest.param(
        [{"type": "phone-number", "number": "+1-234-567-8901", "id": "phone-1"}],
        "234",
        ["phone-1"],
        id="match-phone-number-on-number",
    ),
    pytest.param(
        [{"type": "process", "pid": "12399", "id": "process-1"}],
        "123",
        ["process-1"],
        id="match-process-on-pid",
    ),
    pytest.param(
        [{"type": "software", "name": "StaticScan Antivirus", "id": "software-1"}],
        "static",
        ["software-1"],
        id="match-software-on-name",
    ),
    pytest.param(
        [{"type": "url", "value": "https://staticdomain.com/path", "id": "url-1"}],
        "static",
        ["url-1"],
        id="match-url-on-value",
    ),
    pytest.param(
        [{"type": "user-account", "display_name": "Static User", "id": "user-1"}],
        "static",
        ["user-1"],
        id="match-user-account-on-display_name",
    ),
    pytest.param(
        [{"type": "user-agent", "string": "StaticBot/1.0", "id": "agent-1"}],
        "static",
        ["agent-1"],
        id="match-user-agent-on-string",
    ),
    pytest.param(
        [
            {
                "type": "windows-registry-key",
                "key": "HKEY_LOCAL_MACHINE\\Software\\StaticKey",
                "id": "regkey-1",
            }
        ],
        "statickey",
        ["regkey-1"],
        id="match-registry-key-on-key",
    ),
    pytest.param(
        [
            {
                "type": "x509-certificate",
                "subject": "CN=StaticCert Authority",
                "id": "cert-1",
            }
        ],
        "static",
        ["cert-1"],
        id="match-x509-certificate-on-subject",
    ),
    pytest.param(
        sco_objects,
        "123",
        ["as-1", "regkey-1", "ipv4-1", "phone-1", "process-1"],
        id="match-mixed-all-types-only-5-match-123",
    ),
]


@pytest.mark.parametrize(
    ["objects", "value", "expected_ids"], SCO_VALUE_FILTER_TEST_DATA
)
def test_get_scos_value_filter(objects, value, expected_ids):
    helper = ArangoDBHelper(
        conf.ARANGODB_DATABASE_VIEW, request_from_queries(value=value)
    )
    with make_s2a_uploads(
        [("test_sco_values", objects)], truncate_collection=True
    ) as s2a:
        response_data = helper.get_scos().data
        objects = response_data["objects"]
        object_ids = {obj["id"] for obj in objects}
        assert object_ids == set(expected_ids)


def test_get_scos_type_filter(subtests):
    types = {obj["type"] for obj in sco_objects}
    with make_s2a_uploads(
        [("test_sco_values", sco_objects)], truncate_collection=True
    ) as s2a:
        for _ in range(20):
            expected_types = random.choices(list(types), k=random.randint(5, 10))
            with subtests.test(types=expected_types):
                helper = ArangoDBHelper(
                    conf.ARANGODB_DATABASE_VIEW,
                    request_from_queries(types=",".join(expected_types)),
                )
                response_data = helper.get_scos().data
                objects = response_data["objects"]
                object_types = {obj["type"] for obj in objects}
                assert object_types == set(expected_types)


@pytest.fixture(scope="module")
def sdo_data():
    objects = [
        {
            "type": "weakness",
            "id": "weakness--ac6f22ba-3909-43fa-8f81-1997590a1d7e",
            "labels": ["weak label 1", "strong label 2"],
            "name": "a weakness object",
        },
        {
            "type": "weakness",
            "id": "weakness--cbd67181-b9f8-595b-8bc3-3971e34fa1cc",
            "labels": ["weak label 3"],
            "name": "another weakness object",
        },
        {
            "type": "vulnerability",
            "id": "vulnerability--cbd67181-b9f8-595b-8bc3-3971e34fa1cc",
            "labels": ["weak label 3"],
            "name": "another vulnerability object",
        },
    ]
    with make_s2a_uploads(
        [("test_sdo_filters", objects)], truncate_collection=True
    ) as s2a:
        yield objects


@pytest.mark.parametrize(
    ["filters", "expected_ids"],
    [
        (
            dict(labels="weak"),
            [
                "vulnerability--cbd67181-b9f8-595b-8bc3-3971e34fa1cc",
                "weakness--cbd67181-b9f8-595b-8bc3-3971e34fa1cc",
                "weakness--ac6f22ba-3909-43fa-8f81-1997590a1d7e",
            ],
        ),
        (
            dict(labels="weak", types="weakness"),
            [
                "weakness--cbd67181-b9f8-595b-8bc3-3971e34fa1cc",
                "weakness--ac6f22ba-3909-43fa-8f81-1997590a1d7e",
            ],
        ),
        (
            dict(types="weakness", name="another"),
            ["weakness--cbd67181-b9f8-595b-8bc3-3971e34fa1cc"],
        ),
        (dict(labels="strong"), ["weakness--ac6f22ba-3909-43fa-8f81-1997590a1d7e"]),
    ],
)
def test_sdo_filters(sdo_data, filters, expected_ids):
    helper = ArangoDBHelper(
        conf.ARANGODB_DATABASE_VIEW,
        request_from_queries(**filters),
    )
    assert {obj["id"] for obj in helper.get_sdos().data["objects"]} == set(expected_ids)


@pytest.mark.parametrize(
    "stix_id",
    [
        "vulnerability--cbd67181-b9f8-595b-8bc3-3971e34fa1cc",
        "weakness--cbd67181-b9f8-595b-8bc3-3971e34fa1cc",
        "weakness--ac6f22ba-3909-43fa-8f81-1997590a1d7e",
        "relationship--8a5a7ecf-56cc-4ca5-947f-088870f54ea9",
        "relationship--9cf0369a-8646-4979-ae2c-ab0d3c95bfad",
        "relationship--ce65bbc0-5715-4d44-a24f-42b9757d36f4",
    ],
)
def test_get_objects_by_id(sro_data, sdo_data, stix_id):
    helper = ArangoDBHelper(
        conf.ARANGODB_DATABASE_VIEW,
        request_from_queries(),
    )
    data = helper.get_objects_by_id(stix_id).data
    assert data["id"] == stix_id

@pytest.mark.parametrize(
    "stix_id",
    [
        "bad_id1",
        "bad_id2",
        "bad_id3",
    ]
)
def test_get_objects_by_id__bad_id(sro_data, sdo_data, stix_id):
    helper = ArangoDBHelper(
        conf.ARANGODB_DATABASE_VIEW,
        request_from_queries(),
    )
    with pytest.raises(NotFound):
        data = helper.get_objects_by_id(stix_id).data


@pytest.fixture(scope="module")
def sro_data():
    objects = [
        {
            "type": "relationship",
            "id": "relationship--9cf0369a-8646-4979-ae2c-ab0d3c95bfad",
            "source_ref": "ex-type1--2",
            "target_ref": "ex-type2--2",
            "relationship_type": "created-for",
        },  # SRO1
        {
            "type": "relationship",
            "id": "relationship--1162f86e-c825-4b20-a69e-ea8a6d9d3948",
            "source_ref": "ex-type2--3",
            "target_ref": "ex-type3--3",
            "relationship_type": "killed-by",
        },  # SRO2
        {
            "type": "relationship",
            "id": "relationship--ce65bbc0-5715-4d44-a24f-42b9757d36f4",
            "source_ref": "ex-type3--3",
            "target_ref": "ex-type2--3",
            "relationship_type": "exists-for",
        },  # SRO3
        {
            "type": "relationship",
            "id": "relationship--8a5a7ecf-56cc-4ca5-947f-088870f54ea9",
            "source_ref": "ex-type2--3",
            "target_ref": "ex-type1--3",
            "relationship_type": "exists-for",
            "_is_ref": True,
        },  # SRO3
    ]
    with make_s2a_uploads(
        [("test_sro_filters", objects)], truncate_collection=True
    ) as s2a:
        yield objects


@pytest.mark.parametrize(
    ["filters", "expected_ids"],
    [
        (
            dict(source_ref_type="ex-type2"),
            [
                "relationship--8a5a7ecf-56cc-4ca5-947f-088870f54ea9",
                "relationship--1162f86e-c825-4b20-a69e-ea8a6d9d3948",
            ],
        ),
        (
            dict(target_ref_type="ex-type2"),
            [
                "relationship--9cf0369a-8646-4979-ae2c-ab0d3c95bfad",
                "relationship--ce65bbc0-5715-4d44-a24f-42b9757d36f4",
            ],
        ),
        (
            dict(target_ref_type="ex-type2", source_ref_type="ex-type3"),
            [
                "relationship--ce65bbc0-5715-4d44-a24f-42b9757d36f4",
            ],
        ),
        (
            dict(relationship_type="for"),
            [
                "relationship--8a5a7ecf-56cc-4ca5-947f-088870f54ea9",
                "relationship--9cf0369a-8646-4979-ae2c-ab0d3c95bfad",
                "relationship--ce65bbc0-5715-4d44-a24f-42b9757d36f4",
            ],
        ),
        (
            dict(relationship_type="for", target_ref_type="ex-type2"),
            [
                "relationship--9cf0369a-8646-4979-ae2c-ab0d3c95bfad",
                "relationship--ce65bbc0-5715-4d44-a24f-42b9757d36f4",
            ],
        ),
        (
            dict(include_embedded_refs="false"),
            [
                "relationship--9cf0369a-8646-4979-ae2c-ab0d3c95bfad",
                "relationship--1162f86e-c825-4b20-a69e-ea8a6d9d3948",
                "relationship--ce65bbc0-5715-4d44-a24f-42b9757d36f4",
            ],
        ),
        (
            dict(target_ref="sd"),
            [],
        ),
        (
            dict(target_ref="ex-type1--3"),
            ["relationship--8a5a7ecf-56cc-4ca5-947f-088870f54ea9"],
        ),
        (
            dict(source_ref="ex-type1--2"),
            [
                "relationship--9cf0369a-8646-4979-ae2c-ab0d3c95bfad",
            ],
        ),
    ],
)
def test_sro_filters(sro_data, filters, expected_ids):
    helper = ArangoDBHelper(
        conf.ARANGODB_DATABASE_VIEW,
        request_from_queries(**filters),
    )
    assert {obj["id"] for obj in helper.get_sros().data["objects"]} == set(expected_ids)


@pytest.fixture(scope="module")
def sro_data():
    objects = SRO_DATA
    with make_s2a_uploads(
        [("test_sro_filters", objects)], truncate_collection=True
    ) as s2a:
        yield objects


green_ref, red_ref, clear_ref = (
    "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
    "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
)


@pytest.fixture(scope="module")
def bundle_data():
    objects = SRO_DATA + [
        {"id": "ex-type1--2", "type": "ex-type1"},
        {
            "id": "ex-type2--2",
            "type": "ex-type2",
            "created_by_ref": "ref1",
            "object_marking_refs": [green_ref],
        },
        {
            "id": "ex-type2--3",
            "type": "ex-type2",
            "created_by_ref": "ref2",
            "object_marking_refs": [red_ref],
        },
        {"id": "ex-type3--3", "type": "ex-type3"},
        {
            "id": "ex-type1--3",
            "type": "ex-type1",
            "created_by_ref": "ref2",
            "object_marking_refs": [clear_ref],
        },
        {
            "type": "relationship",
            "id": "relationship--red",
            "source_ref": "ex-type1--2",
            "target_ref": "ex-type2--3",
            "created_by_ref": "ref1",
            "object_marking_refs": [red_ref],
            "relationship_type": "exists-for",
        },  # SRO3
        {
            "type": "relationship",
            "id": "relationship--clear",
            "_is_ref": True,
            "source_ref": "ex-type1--2",
            "target_ref": "ex-type1--3",
            "created_by_ref": "ref2",
            "relationship_type": "exists-for",
            "object_marking_refs": [green_ref],
        },  # SRO3
    ]

    with make_s2a_uploads(
        [("test_bundle_filters", objects)], truncate_collection=True
    ) as s2a:
        yield objects


@pytest.mark.parametrize(
    ["stix_id", "filters", "expected_ids"],
    [
        pytest.param(
            "ex-type1--2",
            None,
            [
                "ex-type1--2",
                "ex-type2--2",
                "ex-type2--3",
                "relationship--9cf0369a-8646-4979-ae2c-ab0d3c95bfad",
                "relationship--red",
                "ex-type1--3",
                "relationship--clear",
            ],
            id='no filters'
        ),
        pytest.param(
            "ex-type1--2",
            dict(visible_to="ref1"),
            [
                "ex-type1--2",
                "ex-type2--2",
                "relationship--9cf0369a-8646-4979-ae2c-ab0d3c95bfad",
                "relationship--red",
                "ex-type1--3",
                "relationship--clear",
            ],
            id='visible_to:ref1'
        ),
        pytest.param(
            "ex-type1--2",
            dict(visible_to="ref2"),
            [
                "ex-type1--2",
                "ex-type2--3",
                "ex-type2--2",
                "relationship--9cf0369a-8646-4979-ae2c-ab0d3c95bfad",
                "ex-type1--3",
                "relationship--clear",
            ],
            id='visible_to:ref2'
        ),
        pytest.param(
            "ex-type1--2",
            dict(visible_to="ref2", include_embedded_refs="false"),
            [
                "ex-type1--2",
                "ex-type2--3",
                "relationship--9cf0369a-8646-4979-ae2c-ab0d3c95bfad",
                "ex-type2--2",
            ],
            id='visible_to:ref2, include_embedded_refs:False'
        ),
        pytest.param(
            "ex-type1--2",
            dict(types="ex-type2,relationship", include_embedded_refs="false"),
            [
                'relationship--red',
                "relationship--9cf0369a-8646-4979-ae2c-ab0d3c95bfad",
                "ex-type2--3",
                "ex-type2--2",
            ],
            id='types:list[1], include_embedded_refs:False'
        ),

        pytest.param(
            "ex-type1--2",
            dict(types="ex-type2,relationship", include_embedded_refs="false", visible_to='ref1'),
            [
                'relationship--red',
                "relationship--9cf0369a-8646-4979-ae2c-ab0d3c95bfad",
                "ex-type2--2",
            ],
            id='types:list[1], include_embedded_refs:False, visible_to:ref1'
        ),

        pytest.param(
            "ex-type1--2",
            dict(types="ex-type2", include_embedded_refs="false", visible_to='ref1'),
            [
                "ex-type2--2",
            ],
            id='types:list[2], include_embedded_refs:False, visible_to:ref1'
        ),
    ],
)
def test_get_object_bundle(bundle_data, stix_id, filters, expected_ids):
    filters = filters or {}
    helper = ArangoDBHelper(
        conf.ARANGODB_DATABASE_VIEW,
        request_from_queries(**filters),
    )
    objects = helper.get_object_bundle(stix_id).data["objects"]
    assert {
        obj["id"] for obj in objects
    } == set(expected_ids)

    if visible_to := filters.get('visible_to'):
        for obj in objects:
            assert obj.get('created_by_ref') in [None, visible_to] or not set(obj.get('object_marking_refs', [])).isdisjoint([green_ref, clear_ref])
    
    if types := filters.get('types'):
        types = types.split(',')
        assert {obj['type'] for obj in objects} == set(types)

@pytest.mark.parametrize(
    "path",
    [
        "/objects/sdos/",
        "/objects/sros/"
    ]
)
@pytest.mark.parametrize(
    "identity_ref",
    [
        "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
        "identity--72e906ce-ca1b-5d73-adcd-9ea9eb66a1b4",
        "identity--bad-identity",
    ]
)
def test_visible_to(client, path, identity_ref):
    resp = client.get(path, query_params=dict(visible_to=identity_ref))
    objects = resp.data["objects"]
    for obj in objects:
        assert obj.get('created_by_ref') in [None, identity_ref] or not set(obj.get('object_marking_refs', [])).isdisjoint([green_ref, clear_ref])