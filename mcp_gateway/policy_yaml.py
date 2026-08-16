#!/usr/bin/env python3
"""
Shared YAML loader for policy files.

Extends PyYAML's SafeLoader with a general-purpose `!concat` tag that:
  - merges a sequence of mappings (like an explicit merge key), or
  - concatenates a sequence of sequences into a flat list.

This lets policies compose shared allow-lists from anchors/aliases, e.g.
`binary: !concat [*sudo, *nonsudo_extra]`, and works anywhere in the policy
tree (match fields, inject.env, backend args, compound backends, ...).

Subclassing SafeLoader preserves all of PyYAML's safety guarantees (no
arbitrary object construction) while adding just this one tag.
"""

import yaml


class PolicyLoader(yaml.SafeLoader):
    """SafeLoader extended with a general-purpose !concat tag."""


def _concat_constructor(loader, node):
    """Resolve `!concat [a, b, ...]`.

    - If every element is a mapping, merge them (later keys win).
    - Otherwise concatenate sequences into a flat list (nested lists are
      flattened; scalar elements are appended as-is).

    Children are constructed via construct_sequence/construct_mapping directly
    (not construct_object) to bypass PyYAML's constructed_objects cache: an
    anchored node referenced both at the top level and inside `!concat` would
    otherwise resolve to its partially-constructed (empty) container.
    """
    seq = []
    for child in node.value:
        if isinstance(child, yaml.SequenceNode):
            seq.append(loader.construct_sequence(child, deep=True))
        elif isinstance(child, yaml.MappingNode):
            seq.append(loader.construct_mapping(child, deep=True))
        else:
            seq.append(loader.construct_object(child, deep=True))

    if all(isinstance(i, dict) for i in seq):
        result = {}
        for item in seq:
            result.update(item)
        return result

    result = []
    for item in seq:
        if isinstance(item, list):
            result.extend(item)
        else:
            result.append(item)
    return result


PolicyLoader.add_constructor("!concat", _concat_constructor)


def load_policy_yaml(stream):
    """Load a policy YAML document with the extended loader."""
    return yaml.load(stream, Loader=PolicyLoader)