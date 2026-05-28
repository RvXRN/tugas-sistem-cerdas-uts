import collections
from collections import abc

# Patch untuk experta compatibility di Python 3.10+
collections.Mapping = abc.Mapping
collections.MutableMapping = abc.MutableMapping
collections.Sequence = abc.Sequence
collections.Iterable = abc.Iterable
