SRO_DATA = [
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