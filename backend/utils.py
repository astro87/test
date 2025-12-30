import math
import hashlib
from typing import List, Any, Generator

def chunk_list(data: List[Any], chunk_size: int) -> Generator[List[Any], None, None]:
    """Yield successive n-sized chunks from data."""
    for i in range(0, len(data), chunk_size):
        yield data[i:i + chunk_size]

class BloomFilter:
    """
    A simple pure-Python Bloom Filter implementation.
    """
    def __init__(self, n: int, p: float):
        """
        n: Expected number of items
        p: False positive probability
        """
        self.m = self._get_size(n, p)
        self.k = self._get_hash_count(self.m, n)
        self.bit_array = [0] * self.m

    def _get_size(self, n: int, p: float) -> int:
        """
        Return the size of bit array(m) to used using
        following formula:
        m = -(n * lg(p)) / (lg(2)^2)
        """
        m = -(n * math.log(p)) / (math.log(2) ** 2)
        return int(m)

    def _get_hash_count(self, m: int, n: int) -> int:
        """
        Return the hash function(k) to be used using
        following formula:
        k = (m/n) * lg(2)
        """
        k = (m / n) * math.log(2)
        return int(k)

    def add(self, item: str):
        """
        Add an item to Bloom filter
        """
        for i in range(self.k):
            digest = hashlib.md5((str(i) + item).encode('utf-8')).hexdigest()
            index = int(digest, 16) % self.m
            self.bit_array[index] = 1

    def check(self, item: str) -> bool:
        """
        Check for existence of an item in filter
        """
        for i in range(self.k):
            digest = hashlib.md5((str(i) + item).encode('utf-8')).hexdigest()
            index = int(digest, 16) % self.m
            if self.bit_array[index] == 0:
                return False
        return True
