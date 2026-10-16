"""Reconstruct confirmations from the exact DebugLink pages shown on screen."""

import re

from keepkeylib import types_pb2 as types


_PAGE = re.compile(r'^(.*) ([1-9][0-9]*)/([1-9][0-9]*)$')


class ConfirmationPages:
    def __init__(self):
        self.raw = []
        self.records = []
        self.texts = []
        self.pending = None

    def add(self, code, text):
        title, body = text
        self.raw.append((code, title, body))
        match = _PAGE.fullmatch(title)
        if not match:
            assert self.pending is None, 'confirmation ended before its last page'
            self.records.append((code, title, body))
            self.texts.append(text)
            return title

        title, index, total = match.groups()
        index, total = int(index), int(total)
        assert 1 <= index <= total <= 99 and total > 1, 'invalid page count'
        if index == 1:
            assert self.pending is None, 'confirmation restarted before its last page'
            self.records.append((code, title, body))
            self.texts.append((title, body))
        else:
            assert self.pending == (title, index, total), 'missing or reordered page'
            assert code == types.ButtonRequest_Other, 'continuation has wrong request code'
            first_code, _, previous = self.records[-1]
            self.records[-1] = (first_code, title, previous + body)
            self.texts[-1] = (title, previous + body)
        self.pending = (title, index + 1, total) if index < total else None
        return title

    def finish(self):
        assert self.pending is None, 'confirmation ended before its last page'
        return self.records

    def __iter__(self):
        return iter(self.finish())

    def __getitem__(self, index):
        return self.finish()[index]

    def __len__(self):
        return len(self.finish())
