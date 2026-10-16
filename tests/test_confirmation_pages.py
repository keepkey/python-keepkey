import pytest

from confirmation_pages import ConfirmationPages
from keepkeylib import types_pb2 as types


OUTPUT = types.ButtonRequest_ConfirmOutput
OTHER = types.ButtonRequest_Other


def test_every_page_is_joined_in_order_without_deduplicating_text():
    pages = ConfirmationPages()
    pages.add(OUTPUT, ('Address 1/3', 'abc'))
    pages.add(OTHER, ('Address 2/3', 'abc'))
    pages.add(OTHER, ('Address 3/3', 'def'))
    pages.add(OUTPUT, ('Address', 'abcabcdef'))
    assert list(pages) == [(OUTPUT, 'Address', 'abcabcdef')] * 2
    assert len(pages.raw) == 4


@pytest.mark.parametrize('next_code,next_title', [
    (OTHER, 'Address 3/3'), (OTHER, 'Address 1/3'),
    (OTHER, 'Address 2/4'), (OTHER, 'Other 2/3'),
    (OUTPUT, 'Address 2/3'), (OUTPUT, 'Done'),
])
def test_missing_repeated_or_changed_pages_fail(next_code, next_title):
    pages = ConfirmationPages()
    pages.add(OUTPUT, ('Address 1/3', 'abc'))
    with pytest.raises(AssertionError):
        pages.add(next_code, (next_title, 'def'))


def test_incomplete_and_orphaned_sequences_fail():
    pages = ConfirmationPages()
    with pytest.raises(AssertionError):
        pages.add(OTHER, ('Address 2/2', 'def'))
    pages = ConfirmationPages()
    pages.add(OUTPUT, ('Address 1/2', 'abc'))
    with pytest.raises(AssertionError):
        list(pages)
