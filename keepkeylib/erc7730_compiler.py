"""Deterministic compiler for KeepKey's bounded ERC-7730 calldata format.

The compiler intentionally emits the small authenticated instruction set
understood by firmware.  It never decodes transaction values: paths and ABI
types are compiled here, while values are decoded again by the device.
"""

from __future__ import absolute_import

import hashlib
import json
import re
import struct

from .signed_metadata import keccak256


ABSENT = 0xffff
HEADER_SIZE = 179
COMPILER_ID = hashlib.sha256(b"python-keepkey:erc7730-compiler:1").digest()


def _u16(value):
    if value < 0 or value > 0xffff:
        raise ValueError("u16 overflow")
    return struct.pack(">H", value)


def _u32(value):
    if value < 0 or value > 0xffffffff:
        raise ValueError("u32 overflow")
    return struct.pack(">I", value)


def _u64(value):
    if value < 0 or value > 0xffffffffffffffff:
        raise ValueError("u64 overflow")
    return struct.pack(">Q", value)


def _i32(value):
    return struct.pack(">i", value)


def _hex_address(value):
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ValueError("address must be 0x-prefixed")
    raw = bytes.fromhex(value[2:])
    if len(raw) != 20:
        raise ValueError("address must be 20 bytes")
    return raw


def _unsigned_literal(value):
    value = int(value)
    if value < 0 or value >= (1 << 256):
        raise ValueError("unsigned literal out of range")
    width = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(width, "big")


class AbiType(object):
    def __init__(self, kind, name="", size=0, children=None,
                 array_length=None):
        self.kind = kind
        self.name = name
        self.size = size
        self.children = list(children or ())
        self.array_length = array_length


class _SignatureParser(object):
    _ident = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")

    def __init__(self, text):
        self.text = text
        self.pos = 0

    def _space(self):
        while self.pos < len(self.text) and self.text[self.pos].isspace():
            self.pos += 1

    def _take(self, token):
        self._space()
        if not self.text.startswith(token, self.pos):
            raise ValueError("expected %s at %d" % (token, self.pos))
        self.pos += len(token)

    def _name(self, required=True):
        self._space()
        match = self._ident.match(self.text, self.pos)
        if not match:
            if required:
                raise ValueError("expected identifier at %d" % self.pos)
            return ""
        self.pos = match.end()
        return match.group(0)

    def type(self):
        self._space()
        if self.pos < len(self.text) and self.text[self.pos] == "(":
            self.pos += 1
            children = []
            self._space()
            if self.pos >= len(self.text) or self.text[self.pos] != ")":
                while True:
                    child = self.type()
                    child.name = self._name(False)
                    children.append(child)
                    self._space()
                    if self.pos < len(self.text) and self.text[self.pos] == ",":
                        self.pos += 1
                        continue
                    break
            self._take(")")
            node = AbiType(8, children=children)
        else:
            token = self._name()
            if token.startswith("uint"):
                bits = int(token[4:] or "256")
                if bits < 8 or bits > 256 or bits % 8:
                    raise ValueError("invalid uint width")
                node = AbiType(1, size=bits)
            elif token.startswith("int"):
                bits = int(token[3:] or "256")
                if bits < 8 or bits > 256 or bits % 8:
                    raise ValueError("invalid int width")
                node = AbiType(2, size=bits)
            elif token == "address":
                node = AbiType(3)
            elif token == "bool":
                node = AbiType(4)
            elif token == "bytes":
                node = AbiType(6)
            elif token.startswith("bytes"):
                width = int(token[5:])
                if width < 1 or width > 32:
                    raise ValueError("invalid bytes width")
                node = AbiType(5, size=width)
            elif token == "string":
                node = AbiType(7)
            else:
                raise ValueError("unsupported ABI type %s" % token)
        while True:
            self._space()
            if self.pos >= len(self.text) or self.text[self.pos] != "[":
                break
            self.pos += 1
            self._space()
            start = self.pos
            while self.pos < len(self.text) and self.text[self.pos].isdigit():
                self.pos += 1
            length = (ABSENT if self.pos == start
                      else int(self.text[start:self.pos]))
            self._take("]")
            node = AbiType(9, children=[node], array_length=length)
        return node

    def function(self):
        name = self._name()
        self._take("(")
        args = []
        self._space()
        if self.pos >= len(self.text) or self.text[self.pos] != ")":
            while True:
                arg = self.type()
                arg.name = self._name(False)
                args.append(arg)
                self._space()
                if self.pos < len(self.text) and self.text[self.pos] == ",":
                    self.pos += 1
                    continue
                break
        self._take(")")
        self._space()
        if self.pos != len(self.text):
            raise ValueError("trailing function signature text")
        return name, AbiType(8, children=args)


def parse_function_signature(signature):
    return _SignatureParser(signature).function()


def _canonical_type(node):
    names = {1: "uint%d", 2: "int%d", 3: "address", 4: "bool",
             5: "bytes%d", 6: "bytes", 7: "string"}
    if node.kind == 8:
        value = "(" + ",".join(_canonical_type(c) for c in node.children) + ")"
    elif node.kind in (1, 2, 5):
        value = names[node.kind] % node.size
    elif node.kind in names:
        value = names[node.kind]
    elif node.kind == 9:
        suffix = "" if node.array_length == ABSENT else str(node.array_length)
        value = _canonical_type(node.children[0]) + "[" + suffix + "]"
    else:
        raise ValueError("invalid ABI kind")
    return value


def _flatten_abi(root):
    nodes = [None]

    def fill(node, index):
        first = 0
        count = len(node.children)
        if count:
            first = len(nodes)
            nodes.extend([None] * count)
        nodes[index] = (node, first, count)
        for offset, child in enumerate(node.children):
            fill(child, first + offset)

    fill(root, 0)
    if len(nodes) > 64:
        raise ValueError("ABI exceeds firmware node limit")
    return nodes


def _resolve_path(root, expression):
    if not isinstance(expression, str) or not expression:
        raise ValueError("invalid ERC-7730 path")
    if expression == "#":
        return []
    if expression.startswith("#."):
        expression = expression[2:]
    if expression.startswith("@."):
        container = {"from": 1, "to": 2, "value": 3, "chainId": 4,
                     "domain": 5, "primaryType": 6}
        name = expression[2:]
        if name not in container:
            raise ValueError("unknown container path %s" % expression)
        return [("container", container[name])]
    parts = expression.split(".")
    node = root
    steps = []
    for part in parts:
        if part.startswith("[") and part.endswith("]"):
            body = part[1:-1]
            if body == "":
                if node.kind != 9:
                    raise ValueError("array iteration applied to non-array")
                steps.append((2,))
                node = node.children[0]
                continue
            if ":" in body:
                start, end = body.split(":", 1)
                flags = (1 if start else 0) | (2 if end else 0)
                steps.append((3, flags,
                              int(start) if start else None,
                              int(end) if end else None))
                continue
            if node.kind != 9:
                raise ValueError("array index applied to non-array")
            index = int(body)
            steps.append((1, index))
            node = node.children[0]
            continue
        if node.kind != 8:
            raise ValueError("field applied to non-tuple")
        matches = [i for i, child in enumerate(node.children)
                   if child.name == part]
        if len(matches) != 1:
            raise ValueError("unknown or ambiguous path component %s" % part)
        index = matches[0]
        steps.append((1, index))
        node = node.children[index]
    if len(steps) > 16:
        raise ValueError("path exceeds firmware limit")
    return steps


def _path_node(root, steps):
    if steps and steps[0][0] == "container":
        # from/to are addresses; value/chainId are unsigned integers. Domain
        # and primaryType are containers and cannot be formatted as leaves.
        kind = 3 if steps[0][1] in (1, 2) else 1
        return AbiType(kind)
    node = root
    for step in steps:
        if step[0] == 1:
            if node.kind == 8:
                node = node.children[step[1]]
            elif node.kind == 9:
                node = node.children[0]
            else:
                raise ValueError("path continues through primitive")
        elif step[0] == 2:
            if node.kind != 9:
                raise ValueError("iteration through non-array")
            node = node.children[0]
        elif step[0] == 3:
            break
    return node


def _condition_literal(node, value):
    if node.kind == 1 and isinstance(value, int) and not isinstance(value, bool):
        return 1, _unsigned_literal(value)
    if node.kind == 2 and isinstance(value, int) and not isinstance(value, bool):
        width = max(1, (value.bit_length() + 8) // 8)
        return 2, value.to_bytes(width, "big", signed=True)
    if node.kind == 3 and isinstance(value, str):
        return 5, _hex_address(value)
    if node.kind == 4 and isinstance(value, bool):
        return 6, bytes([1 if value else 0])
    if node.kind in (5, 6) and isinstance(value, str) and value.startswith("0x"):
        return 3, bytes.fromhex(value[2:])
    raise ValueError("condition value does not match ABI leaf type")


class CalldataCompiler(object):
    """Compile one calldata format and deployment into canonical C773 bytes."""

    FORMAT_KIND = {"raw": 1, "amount": 2, "tokenAmount": 3,
                   "nftName": 4, "date": 5, "duration": 6,
                   "unit": 7, "enum": 8, "chainId": 9,
                   "addressName": 10, "tokenTicker": 11,
                   "interoperableAddress": 12, "calldata": 13,
                   "encrypted": 14}

    def __init__(self, descriptor, signature, chain_id, address,
                 provider_id=1, issuance_epoch=0, revocation_epoch=0,
                 token_records=(), network_records=(), definition_kind=1,
                 primary_type_hash=None, domain_constraints=()):
        self.descriptor = descriptor
        self.signature = signature
        self.chain_id = int(chain_id)
        self.address = _hex_address(address) if isinstance(address, str) else bytes(address)
        if len(self.address) != 20:
            raise ValueError("contract address must be 20 bytes")
        self.provider_id = provider_id
        self.issuance_epoch = issuance_epoch
        self.revocation_epoch = revocation_epoch
        self.token_records = list(token_records)
        self.network_records = list(network_records)
        self.definition_kind = definition_kind
        self.primary_type_hash = primary_type_hash
        self.domain_constraints = list(domain_constraints)
        if definition_kind not in (1, 2):
            raise ValueError("compiler supports calldata or EIP-712 programs")
        if definition_kind == 2 and (primary_type_hash is None or
                                     len(primary_type_hash) != 32):
            raise ValueError("EIP-712 requires a primary type hash")

    def compile(self):
        function_name, root = parse_function_signature(self.signature)
        canonical_signature = function_name + "(" + ",".join(
            _canonical_type(c) for c in root.children) + ")"
        formats = self.descriptor.get("display", {}).get("formats", {})
        selected = formats.get(self.signature)
        if selected is None:
            for candidate, value in formats.items():
                parsed_name, parsed_root = parse_function_signature(candidate)
                candidate_canonical = parsed_name + "(" + ",".join(
                    _canonical_type(c) for c in parsed_root.children) + ")"
                if candidate_canonical == canonical_signature:
                    selected = value
                    break
        if selected is None:
            raise KeyError("signature is not described")

        def descriptor_value(reference):
            if not isinstance(reference, str) or not reference.startswith("$."):
                return reference
            value = self.descriptor
            for component in reference[2:].split("."):
                if not isinstance(value, dict) or component not in value:
                    raise ValueError("unresolved descriptor value %s" % reference)
                value = value[component]
            return value

        def normalized_path(path):
            return path[2:] if isinstance(path, str) and path.startswith("#.") else path

        def resolve_field(field):
            reference = field.get("$ref")
            if not reference:
                return dict(field)
            prefix = "$.display.definitions."
            if not reference.startswith(prefix):
                raise ValueError("unsupported field reference")
            name = reference[len(prefix):]
            base = self.descriptor.get("display", {}).get(
                "definitions", {}).get(name)
            if not isinstance(base, dict):
                raise ValueError("unresolved field reference")
            result = dict(base)
            result.update((key, value) for key, value in field.items()
                          if key != "$ref" and key != "params")
            params = dict(base.get("params", {}))
            params.update(field.get("params", {}))
            if params:
                result["params"] = params
            return result

        field_specs = []
        group_ranges = []

        def join_path(prefix, path):
            if not prefix or (isinstance(path, str) and
                              path.startswith(("#.", "@.", "$."))):
                return path
            if not path:
                return prefix
            return prefix + "." + path

        def flatten_fields(items, prefix=None):
            for item in items:
                if "fields" not in item:
                    field = dict(item)
                    if "path" in field:
                        field["path"] = join_path(prefix, field["path"])
                    if prefix:
                        field["_path_prefix"] = prefix
                    field_specs.append(field)
                    continue
                group_path = join_path(prefix, item.get("path"))
                if group_path and ".[]" in group_path:
                    # Array-backed groups need an array instruction around the
                    # group and are compiled by the dedicated nested pass.
                    raise ValueError("nested array iteration requires a field group")
                start = len(field_specs)
                flatten_fields(item.get("fields", ()), group_path)
                end = len(field_specs)
                if end == start:
                    raise ValueError("display group must contain a field")
                group_ranges.append((start, end, item.get("label")))

        flatten_fields(selected.get("fields", []))

        strings = set([selected.get("intent", selected.get("$id", function_name))])
        for unused_start, unused_end, group_label in group_ranges:
            if group_label:
                strings.add(group_label)
        interpolation = selected.get("interpolatedIntent")
        interpolation_tokens = []
        if interpolation is not None:
            cursor = 0
            for match in re.finditer(r"\{([^{}]+)\}", interpolation):
                if match.start() > cursor:
                    text = interpolation[cursor:match.start()]
                    strings.add(text)
                    interpolation_tokens.append(("text", text))
                interpolation_tokens.append(("value", match.group(1)))
                cursor = match.end()
            if cursor < len(interpolation):
                text = interpolation[cursor:]
                strings.add(text)
                interpolation_tokens.append(("text", text))
        for record in self.token_records:
            strings.add(record[2])
        for record in self.network_records:
            strings.add(record[1])
            strings.add(record[2])
        for field, value in self.domain_constraints:
            if field in (1, 2):
                strings.add(value)
        fields = []
        for unresolved in field_specs:
            field = resolve_field(unresolved)
            if field.get("visible") == "never":
                continue
            label = field.get("label")
            path = field.get("path")
            constant_value = field.get("value") if "value" in field else None
            kind_name = field.get("format", "raw")
            if (not label or (not path and "value" not in field) or
                    kind_name not in self.FORMAT_KIND):
                raise ValueError("invalid display field")
            strings.add(label)
            if isinstance(constant_value, str) and not constant_value.startswith("0x"):
                strings.add(constant_value)
            params = field.get("params", {})
            prefix = field.get("_path_prefix")
            if prefix:
                params = dict(params)
                for key in ("tokenPath", "collectionPath", "chainIdPath",
                            "calleePath", "selectorPath", "amountPath",
                            "spenderPath"):
                    if key in params:
                        params[key] = join_path(prefix, params[key])
                field["params"] = params
            if kind_name == "enum":
                enum_ref = params.get("$ref")
                prefix = "$.metadata.enums."
                if not isinstance(enum_ref, str) or not enum_ref.startswith(prefix):
                    raise ValueError("enum requires a metadata enum reference")
                enum_values = self.descriptor.get("metadata", {}).get(
                    "enums", {}).get(enum_ref[len(prefix):])
                if not isinstance(enum_values, dict) or not enum_values:
                    raise ValueError("unresolved enum reference")
                for enum_label in enum_values.values():
                    strings.add(enum_label)
            if kind_name == "date":
                strings.add(params.get("encoding", "timestamp"))
            elif kind_name == "unit":
                base = params.get("base")
                if not isinstance(base, str) or not base:
                    raise ValueError("unit requires base")
                strings.add(base)
            elif kind_name == "tokenAmount" and params.get("message"):
                strings.add(params["message"])
            separator = field.get("separator")
            if separator:
                strings.add(separator)
            fields.append((field, (("constant", constant_value),)
                           if "value" in field else _resolve_path(root, path)))
        strings = sorted(s.encode("utf-8") for s in strings)
        if any(not value or len(value) > 128 for value in strings):
            raise ValueError("invalid string length")
        string_index = dict((value.decode("utf-8"), i)
                            for i, value in enumerate(strings))

        paths = []
        path_index = {}
        def intern_path(steps):
            key = tuple(steps)
            if key not in path_index:
                path_index[key] = len(paths)
                paths.append(steps)
            return path_index[key]

        literals = []
        formatters = []
        conditions = []
        optional_condition = None
        displays = [[1, string_index[selected.get("intent", selected.get("$id", function_name))], ABSENT, ABSENT]]
        if interpolation_tokens:
            formatter_by_path = {}
            for index, (field, unused_steps) in enumerate(fields):
                if field.get("visible", "always") == "always":
                    formatter_by_path[normalized_path(field.get("path"))] = index
            for token_kind, token_value in interpolation_tokens:
                if token_kind == "text":
                    displays.append([2, string_index[token_value], ABSENT, ABSENT])
                else:
                    token_value = normalized_path(token_value)
                    if token_value not in formatter_by_path:
                        raise ValueError(
                            "interpolated value must reference an always-visible field")
                    displays.append([3, formatter_by_path[token_value], ABSENT, ABSENT])

        domain_records = []
        for field, value in self.domain_constraints:
            if field in (1, 2):
                literal = (4, _u16(string_index[value]))
            elif field == 3:
                literal = (7, _unsigned_literal(value))
            elif field == 4:
                literal = (5, _hex_address(value) if isinstance(value, str)
                           else bytes(value))
            elif field == 5:
                literal = (3, bytes.fromhex(value[2:])
                           if isinstance(value, str) and value.startswith("0x")
                           else bytes(value))
            else:
                raise ValueError("unknown EIP-712 domain field")
            literals.append(literal)
            domain_records.append((2, bytes([field, 1]) +
                                   _u16(len(literals) - 1)))
        groups_starting = {}
        groups_ending = {}
        for start, end, label in group_ranges:
            groups_starting.setdefault(start, []).append((end, label))
            groups_ending.setdefault(end, []).append((start, label))
        active_group_pcs = []

        for field_number, (field, steps) in enumerate(fields):
            for unused_end, label in sorted(
                    groups_starting.get(field_number, ()), reverse=True):
                begin_pc = len(displays)
                displays.append([5, string_index[label] if label else ABSENT,
                                 ABSENT, 0])
                active_group_pcs.append(begin_pc)
            if steps and steps[0][0] == "constant":
                value = descriptor_value(steps[0][1])
                if isinstance(value, bool):
                    literal = (6, bytes([1 if value else 0]))
                elif isinstance(value, int):
                    literal = (1, _unsigned_literal(value))
                elif isinstance(value, str) and value.startswith("0x"):
                    raw = bytes.fromhex(value[2:])
                    literal = (5 if len(raw) == 20 else 3, raw)
                elif isinstance(value, str):
                    literal = (4, _u16(string_index[value]))
                else:
                    raise ValueError("unsupported constant display value")
                literals.append(literal)
                steps = (("literal", len(literals) - 1),)
            value_path = intern_path(steps)
            kind = self.FORMAT_KIND[field.get("format", "raw")]
            arguments = [(1, 1, value_path)]
            params = field.get("params", {})
            if kind == 3:
                token = params.get("tokenPath")
                if token is None:
                    token = params.get("token")
                token = descriptor_value(token)
                if isinstance(token, str) and token.startswith("0x"):
                    raw = _hex_address(token)
                    literals.append((5, raw))
                    literal_path = intern_path((("literal", len(literals) - 1),))
                    arguments.append((2, 1, literal_path))
                elif isinstance(token, str):
                    arguments.append((2, 1, intern_path(_resolve_path(root, token))))
                else:
                    raise ValueError("tokenAmount requires token or tokenPath")
                if "threshold" in params:
                    threshold = descriptor_value(params["threshold"])
                    if isinstance(threshold, str) and threshold.startswith("0x"):
                        threshold = int(threshold, 16)
                    literals.append((1, _unsigned_literal(threshold)))
                    arguments.append((7, 2, len(literals) - 1))
                if params.get("message"):
                    arguments.append((8, 3, string_index[params["message"]]))
                if "chainId" in params:
                    chain = params["chainId"]
                    if isinstance(chain, int):
                        literals.append((7, _unsigned_literal(chain)))
                        arguments.append((11, 2, len(literals) - 1))
                    elif isinstance(chain, str):
                        arguments.append((11, 1,
                                          intern_path(_resolve_path(root, chain))))
                    else:
                        raise ValueError("invalid tokenAmount chainId")
                aliases = params.get("nativeCurrencyAddress", ())
                aliases = descriptor_value(aliases)
                if aliases:
                    if isinstance(aliases, str):
                        aliases = [aliases]
                    references = []
                    for alias in aliases:
                        alias = descriptor_value(alias)
                        literals.append((5, _hex_address(alias)))
                        references.append(len(literals) - 1)
                    literals.append((9, _u16(len(references)) + b"".join(
                        _u16(index) for index in references)))
                    arguments.append((22, 2, len(literals) - 1))
            elif kind == 4:
                collection = params.get("collectionPath")
                if collection is None:
                    collection = params.get("collection")
                collection = descriptor_value(collection)
                if isinstance(collection, str) and collection.startswith("0x"):
                    literals.append((5, _hex_address(collection)))
                    collection_path = intern_path(
                        (("literal", len(literals) - 1),))
                elif isinstance(collection, str):
                    collection_path = intern_path(_resolve_path(root, collection))
                else:
                    raise ValueError("nftName requires collection or collectionPath")
                arguments.append((3, 1, collection_path))
                chain = params.get("chainIdPath", params.get("chainId"))
                if chain is not None:
                    chain = descriptor_value(chain)
                    if isinstance(chain, int):
                        literals.append((7, _unsigned_literal(chain)))
                        arguments.append((11, 2, len(literals) - 1))
                    elif isinstance(chain, str):
                        arguments.append((11, 1,
                                          intern_path(_resolve_path(root, chain))))
                    else:
                        raise ValueError("invalid nftName chainId")
            elif kind == 5:
                encoding = params.get("encoding", "timestamp")
                arguments.append((9, 3, string_index[encoding]))
            elif kind == 7:
                decimals = params.get("decimals", 0)
                literals.append((1, _unsigned_literal(decimals)))
                arguments.append((4, 2, len(literals) - 1))
                arguments.append((5, 3, string_index[params["base"]]))
                literals.append((6, bytes([1 if params.get("prefix") else 0])))
                arguments.append((6, 2, len(literals) - 1))
            elif kind == 8:
                enum_ref = params["$ref"]
                enum_values = self.descriptor["metadata"]["enums"][
                    enum_ref[len("$.metadata.enums."):]]
                node = _path_node(root, steps)
                pairs = []
                for raw_key, label in sorted(enum_values.items()):
                    if node.kind == 4:
                        if raw_key not in ("true", "false"):
                            raise ValueError("boolean enum key must be true or false")
                        key = raw_key == "true"
                    elif node.kind in (1, 2):
                        key = int(raw_key, 0)
                    elif node.kind in (3, 5, 6):
                        key = raw_key
                    else:
                        raise ValueError("enum requires a scalar ABI value")
                    literals.append(_condition_literal(node, key))
                    pairs.append((len(literals) - 1, string_index[label]))
                pairs.sort()
                literals.append((8, _u16(len(pairs)) + b"".join(
                    _u16(key) + _u16(value) for key, value in pairs)))
                arguments.append((10, 2, len(literals) - 1))
            elif kind == 13:
                callee = params.get("calleePath")
                if not callee:
                    raise ValueError("embedded calldata requires calleePath")
                arguments.append((15, 1, intern_path(_resolve_path(root, callee))))
            formatter_index = len(formatters)
            formatters.append((kind, arguments))
            condition = ABSENT
            visibility = field.get("visible")
            if visibility == "optional":
                if optional_condition is None:
                    optional_condition = len(conditions)
                    conditions.append((3, ABSENT, ABSENT))
                condition = optional_condition
            elif isinstance(visibility, dict):
                keys = [key for key in ("ifNotIn", "mustMatch")
                        if key in visibility]
                if len(keys) != 1 or not visibility[keys[0]]:
                    raise ValueError("invalid visibility rule")
                references = []
                node = _path_node(root, steps)
                for value in visibility[keys[0]]:
                    literal = _condition_literal(node, value)
                    literals.append(literal)
                    references.append(len(literals) - 1)
                set_value = _u16(len(references)) + b"".join(
                    _u16(index) for index in references)
                literals.append((9, set_value))
                condition = len(conditions)
                conditions.append((7 if keys[0] == "ifNotIn" else 8,
                                   value_path, len(literals) - 1))
            all_positions = [i for i, step in enumerate(steps)
                             if step[0] == 2]
            if all_positions:
                begins = []
                for position in all_positions:
                    array_path = intern_path(steps[:position + 1])
                    begin = len(displays)
                    begins.append(begin)
                    displays.append([7, array_path, condition, 0])
                displays.append([4, string_index[field["label"]],
                                 formatter_index, ABSENT])
                separator = field.get("separator")
                for depth, begin in enumerate(reversed(begins)):
                    end = len(displays)
                    displays.append([
                        8, begin,
                        (string_index[separator]
                         if separator and depth == len(begins) - 1 else ABSENT),
                        ABSENT])
                    displays[begin][3] = end
            else:
                displays.append([4, string_index[field["label"]],
                                 formatter_index, condition])
            for unused_start, unused_label in reversed(
                    groups_ending.get(field_number + 1, ())):
                if not active_group_pcs:
                    raise ValueError("unbalanced display group")
                begin_pc = active_group_pcs.pop()
                end_pc = len(displays)
                displays.append([6, begin_pc, ABSENT, ABSENT])
                displays[begin_pc][3] = end_pc
        if active_group_pcs:
            raise ValueError("unbalanced display group")
        displays.append([10, ABSENT, ABSENT, ABSENT])

        if (len(paths) > 64 or len(formatters) > 64 or len(displays) > 64 or
                len(conditions) > 32):
            raise ValueError("compiled program exceeds table limits")

        sections = []
        payload = _u16(len(strings)) + b"".join(_u16(len(s)) + s for s in strings)
        sections.append((1, payload))
        flat = _flatten_abi(root)
        payload = _u16(len(flat))
        def depth(node):
            return 1 + (max(depth(child) for child in node.children)
                        if node.children else 0)
        max_depth = depth(root)
        for node, first, count in flat:
            array_length = node.array_length if node.kind == 9 else 0
            payload += bytes([node.kind]) + _u16(node.size) + _u16(first) + _u16(count) + _u16(array_length or 0)
        sections.append((2, payload))
        payload = _u16(len(paths))
        for steps in paths:
            if steps and steps[0][0] == "literal":
                payload += bytes([3, 0]) + _u16(steps[0][1])
                continue
            if steps and steps[0][0] == "container":
                payload += bytes([2, 0]) + _u16(steps[0][1])
                continue
            payload += bytes([1, len(steps)]) + _u16(ABSENT)
            for step in steps:
                if step[0] == 1:
                    payload += bytes([1]) + _i32(step[1])
                elif step[0] == 2:
                    payload += bytes([2])
                else:
                    payload += bytes([3, step[1]])
                    if step[1] & 1:
                        payload += _i32(step[2])
                    if step[1] & 2:
                        payload += _i32(step[3])
        sections.append((3, payload))
        if literals:
            payload = _u16(len(literals)) + b"".join(
                bytes([kind]) + _u16(len(value)) + value
                for kind, value in literals)
            sections.append((4, payload))
        if conditions:
            payload = _u16(len(conditions)) + b"".join(
                bytes([opcode]) + _u16(path) + _u16(literal_set) +
                bytes([0]) + _u16(0)
                for opcode, path, literal_set in conditions)
            sections.append((5, payload))
        payload = _u16(len(formatters))
        for kind, arguments in formatters:
            payload += bytes([kind, 0, len(arguments)])
            for role, source, index in sorted(arguments):
                payload += bytes([role, source]) + _u16(index)
        sections.append((6, payload))
        payload = _u16(len(displays)) + b"".join(
            bytes([op, 0]) + _u16(a) + _u16(b) + _u16(c)
            for op, a, b, c in displays)
        sections.append((7, payload))
        bindings = [(1, _u64(self.chain_id) + self.address)] + domain_records
        for record in self.token_records:
            ticker = record[2]
            if ticker not in string_index:
                raise ValueError("token ticker must be used by display strings")
            bindings.append((3, _u64(record[0]) + _hex_address(record[1]) +
                             _u16(string_index[ticker]) + bytes([record[3]])))
        for record in self.network_records:
            bindings.append((4, _u64(record[0]) +
                             _u16(string_index[record[1]]) +
                             _u16(string_index[record[2]]) +
                             bytes([record[3]])))
        bindings.sort(key=lambda item: (item[0], item[1]))
        payload = _u16(len(bindings)) + b"".join(
            bytes([kind]) + _u16(len(value)) + value for kind, value in bindings)
        sections.append((8, payload))
        display_depth = 0
        display_max_depth = 0
        for instruction in displays:
            if instruction[0] in (5, 7):
                display_depth += 1
                display_max_depth = max(display_max_depth, display_depth)
            elif instruction[0] in (6, 8):
                display_depth -= 1
        if display_depth != 0:
            raise ValueError("unbalanced display program")
        resource = [_u16(len(strings)), _u16(len(flat)), _u16(len(paths)),
                    _u16(len(literals)), _u16(len(conditions)), _u16(len(formatters)),
                    _u16(len(displays)), _u16(len(bindings)),
                    bytes([max_depth,
                           64 if any(step[0] == 2 for path in paths
                                     for step in path) else 0,
                           display_max_depth,
                           1 if any(kind == 13 for kind, _ in formatters) else 0]),
                    _u16(max([len(s) for s in strings] or [0]))]
        sections.append((9, b"".join(resource)))

        source = json.dumps(self.descriptor, sort_keys=True,
                            separators=(",", ":")).encode("utf-8")
        token_hash = hashlib.sha256(b"".join(value for _, value in bindings
                                             if _ != 1)).digest()
        selector = (keccak256(canonical_signature.encode("ascii"))[:4] + bytes(28)
                    if self.definition_kind == 1 else self.primary_type_hash)
        header = (b"C773" + bytes([1, 2, 0, self.definition_kind]) + _u16(0) +
                  _u64(self.chain_id) + self.address + selector +
                  hashlib.sha256(source).digest() + COMPILER_ID + token_hash +
                  _u32(self.provider_id) + _u32(self.issuance_epoch) +
                  _u32(self.revocation_epoch) + bytes([len(sections)]))
        if len(header) != HEADER_SIZE:
            raise AssertionError("invalid C773 header size")
        return header + b"".join(bytes([kind]) + _u32(len(value)) + value
                                 for kind, value in sections)


def compile_calldata(descriptor, signature, chain_id, address, **kwargs):
    return CalldataCompiler(descriptor, signature, chain_id, address,
                            **kwargs).compile()


def _typed_base(type_name, types, active):
    array = re.match(r"^(.*)\[([0-9]*)\]$", type_name)
    if array:
        child = _typed_base(array.group(1), types, active)
        length = ABSENT if array.group(2) == "" else int(array.group(2))
        return AbiType(9, children=[child], array_length=length)
    if type_name in types:
        if type_name in active:
            raise ValueError("recursive EIP-712 type")
        children = []
        for member in types[type_name]:
            child = _typed_base(member["type"], types, active | {type_name})
            child.name = member["name"]
            children.append(child)
        return AbiType(8, children=children)
    parser = _SignatureParser(type_name)
    node = parser.type()
    parser._space()
    if parser.pos != len(type_name):
        raise ValueError("invalid EIP-712 member type")
    return node


def eip712_encode_type(primary_type, types):
    if primary_type not in types:
        raise ValueError("missing EIP-712 primary type")
    dependencies = set()

    def visit(name):
        for member in types[name]:
            base = re.sub(r"\[[0-9]*\]$", "", member["type"])
            if base in types and base != primary_type and base not in dependencies:
                dependencies.add(base)
                visit(base)

    visit(primary_type)
    def declaration(name):
        return name + "(" + ",".join(
            member["type"] + " " + member["name"]
            for member in types[name]) + ")"
    return declaration(primary_type) + "".join(
        declaration(name) for name in sorted(dependencies))


def compile_eip712(descriptor, typed_data, chain_id=None, address=None,
                   **kwargs):
    """Compile one EIP-712 descriptor against its exact typed-data schema."""
    types = typed_data["types"]
    primary = typed_data["primaryType"]
    root = _typed_base(primary, types, set())
    def named(node):
        if node.kind == 8:
            value = "(" + ",".join(
                named(child) + (" " + child.name if child.name else "")
                for child in node.children) + ")"
        elif node.kind == 9:
            suffix = "" if node.array_length == ABSENT else str(node.array_length)
            value = named(node.children[0]) + "[" + suffix + "]"
        else:
            value = _canonical_type(node)
        return value
    signature = primary + "(" + ",".join(
        named(child) + (" " + child.name if child.name else "")
        for child in root.children) + ")"
    formats = descriptor.get("display", {}).get("formats", {})
    selected = None
    for key, value in formats.items():
        if key.startswith(primary + "("):
            selected = value
            break
    if selected is None:
        raise KeyError("primary type is not described")
    synthetic = dict(descriptor)
    synthetic["display"] = dict(descriptor.get("display", {}))
    synthetic["display"]["formats"] = {signature: selected}
    domain = typed_data.get("domain", {})
    if chain_id is None:
        chain_id = domain.get("chainId")
    if address is None:
        address = domain.get("verifyingContract")
    if not chain_id or not address:
        raise ValueError("EIP-712 chain and verifying contract are required")
    constraints = []
    for name, field in (("name", 1), ("version", 2), ("chainId", 3),
                        ("verifyingContract", 4), ("salt", 5)):
        if name in domain:
            constraints.append((field, domain[name]))
    type_hash = keccak256(eip712_encode_type(primary, types).encode("ascii"))
    return CalldataCompiler(
        synthetic, signature, chain_id, address, definition_kind=2,
        primary_type_hash=type_hash, domain_constraints=constraints,
        **kwargs).compile()
