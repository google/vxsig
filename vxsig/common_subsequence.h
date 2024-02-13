// Copyright 2011-2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This header contains a templated algorithm to calculate k-common
// subsequences. For some input instances, it can even compute k-LCS
// efficiently.

#ifndef VXSIG_COMMON_SUBSEQUENCE_H_
#define VXSIG_COMMON_SUBSEQUENCE_H_

#include <algorithm>
#include <iterator>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "absl/base/internal/raw_logging.h"
#include "vxsig/hamming.h"
#include "vxsig/longest_common_subsequence.h"

namespace security::vxsig {

// Removes from the range [first,last) the elements not in the range
// [keep_first, keep_last). That is, PruneSequence returns an iterator new_last
// such that the range [first, new_last) contains no elements from the range
// [keep_first, keep_last). The iterators in the range [new_last, last) are all
// still dereferenceable, but the elements that they point to are unspecified.
// PruneSequence is stable, meaning that the relative order of elements that
// are not equal to value is unchanged.
//
// For a range of length n, and a fixed alphabet size, this function runs in
// linear time and space.
// The worst case running time is O(n^2) for unbounded alphabets.
//
// Returns an iterator to the new end of the pruned range.
template<typename IteratorT, typename KeepIteratorT>
IteratorT PruneSequence(IteratorT first, IteratorT last,
                        KeepIteratorT keep_first, KeepIteratorT keep_last) {
  auto result = first;
  for (; first != last; ++first) {
    if (std::find(keep_first, keep_last, *first) != keep_last) {
      *result++ = *first;
    }
  }
  return result;
}

// Calculates a common subsequence of an arbitrary number of sequences.
//
// This function template calculates a common subsequence of the elements
// contained in the specified standard containers. If the input sequences are
// permutations of the same sequence, this function returns the k-longest common
// subsequence. Otherwise the returned sequence is guaranteed to be a k-common
// subsequence, although not necessarily the longest.
//
// The common subsequence is calculated by first computing the pairwise Hamming
// distances of the input sequences and then folding the two most similar
// sequences into their LCS. The LCS of two sequences is calculated by calling
// LongestCommonSubsequence(). If duplicate sequences are encountered, only one
// copy is kept. The resulting (smaller) problem set is then processed
// recursively.
//
// The worst case performance of this algorithm does not exceed O(n^2 + k * n)
// time and O(n^2) space, where k is the number of input sequences and n the
// maximum length of a sequence.
template <typename NestedContT, typename OutputIteratorT>
void CommonSubsequence(const NestedContT& sequences, OutputIteratorT result) {
  using ValueType = typename NestedContT::value_type::value_type;

  if (sequences.size() < 2) {
    ABSL_RAW_LOG(FATAL, "Invalid number of sequences");
  }

  // Create a modifiable copy of sequences.
  std::vector<std::vector<ValueType>> sub_seqs;
  sub_seqs.reserve(sequences.size());
  for (const auto& sequence : sequences) {
    sub_seqs.emplace_back(sequence.begin(), sequence.end());
  }

  while (sub_seqs.size() > 2) {
    // Find the two sequences with the greatest Hamming distance and
    // populate the removal set.
    size_t max_dist = 0;  // Greatest distance so far.
    // Indices of sequences with smallest distance.
    std::pair<size_t, size_t> shd(0, 0);
    std::set<size_t> removals;  // Indices of sequences to remove.
    for (size_t i = 0; i < sub_seqs.size(); ++i) {
      for (size_t j = 0; j < i; ++j) {
        // Current Hamming distance.
        const size_t cur_dist = HammingDistance(sub_seqs[i], sub_seqs[j]);
        if (cur_dist == 0) {
          removals.insert(removals.end(), i);
        } else if (cur_dist > max_dist) {
          max_dist = cur_dist;
          shd = {i, j};
        }
      }
    }

    if (removals.size() == sub_seqs.size() - 1) {
      // If all sequences are identical, return the first as the common
      // subsequence.
      std::copy(sub_seqs[0].begin(), sub_seqs[0].end(), result);
      return;
    }

    // Call regular 2-LCS algorithm on the two least similar sequences.
    std::vector<ValueType> max_dist_lcs;
    LongestCommonSubsequence(sub_seqs[shd.second].begin(),
                             sub_seqs[shd.second].end(),
                             sub_seqs[shd.first].begin(),
                             sub_seqs[shd.first].end(),
                             back_inserter(max_dist_lcs));

    // Replace the two most similar sequences with their LCS. From all other
    // sequences, remove any element not found in the LCS. Those elements
    // can by definition not be part a CS of all sequences.
    // Also add the most similar sequences to the removal set, since we only
    // keep their LCS which is added back later.
    removals.insert(removals.end(), shd.first);
    removals.insert(removals.end(), shd.second);

    // Reverse traversal ensures that the items relative to the beginning of
    // sub_seqs are valid.
    for (auto it = removals.crbegin(); it != removals.crend(); ++it) {
      sub_seqs.erase(sub_seqs.begin() + *it);
    }

    // Prune all elements not in max_dist_lcs.
    for (auto& sequence : sub_seqs) {
      sequence.erase(PruneSequence(sequence.begin(), sequence.end(),
                                   max_dist_lcs.begin(), max_dist_lcs.end()),
                     sequence.end());
    }

    // Add LCS to sub-problem set as well (since the original sequences
    // were removed).
    sub_seqs.insert(sub_seqs.end(), max_dist_lcs);
  }

  if (sub_seqs.size() == 1) {
    // If only one sequence is left, this is the common subsequence.
    std::copy(sub_seqs[0].begin(), sub_seqs[0].end(), result);
  } else if (sub_seqs.size() == 2) {
    // Problem size 2 is the well-known longest common subsequence problem.
    LongestCommonSubsequence(sub_seqs[0].begin(), sub_seqs[0].end(),
                             sub_seqs[1].begin(), sub_seqs[1].end(), result);
  } else {
    ABSL_RAW_LOG(FATAL, "Invalid number of sub-sequences left: %d",
                 static_cast<int>(sub_seqs.size()));
  }
}

}  // namespace security::vxsig

#endif  // VXSIG_COMMON_SUBSEQUENCE_H_
