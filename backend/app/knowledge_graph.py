"""
Builds a small per-incident knowledge graph linking the incident
to its extracted entities and IoCs using NetworkX.

The graph is exported as node-link JSON for the frontend
(vis-network).
"""

import networkx as nx
from networkx.readwrite import json_graph


def build_incident_graph(
    incident_id: str,
    incident_type: str,
    entities: dict,
    iocs: dict
) -> dict:

    G = nx.Graph()

    # Main incident node
    G.add_node(
        incident_id,
        label=f"Incident: {incident_type}",
        type="incident"
    )

    def add_group(items, node_type, prefix):
        for item in items:
            node_id = f"{prefix}:{item}"

            G.add_node(
                node_id,
                label=item,
                type=node_type
            )

            G.add_edge(
                incident_id,
                node_id
            )

    # Malware
    add_group(
        entities.get("malware_families", []),
        "malware",
        "malware"
    )

    # Organizations
    add_group(
        entities.get("organizations", []),
        "organization",
        "org"
    )

    # Users
    add_group(
        entities.get("users", []),
        "user",
        "user"
    )

    # IP addresses
    add_group(
        iocs.get("ipv4_addresses", []),
        "ip",
        "ip"
    )

    # Domains
    add_group(
        iocs.get("domains", []),
        "domain",
        "domain"
    )

    # CVEs
    add_group(
        iocs.get("cves", []),
        "cve",
        "cve"
    )

    # File hashes
    for hash_type, hashes in iocs.get("file_hashes", {}).items():
        add_group(
            hashes,
            "hash",
            f"hash-{hash_type}"
        )

    # Use NetworkX's default node-link format.
    # This produces "nodes" and "links".
    return json_graph.node_link_data(G)


def merge_graphs(graph_dicts: list) -> dict:
    """
    Combine multiple per-incident graphs into one
    cross-incident graph.
    """

    G = nx.Graph()

    for gd in graph_dicts:

        # Read the standard NetworkX node-link format.
        g = json_graph.node_link_graph(gd)

        # Merge into combined graph.
        G = nx.compose(G, g)

    # Return standard node-link JSON.
    return json_graph.node_link_data(G)