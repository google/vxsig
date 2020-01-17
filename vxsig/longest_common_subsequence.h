// Copyright 2011-2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// A templated version of the longest-common-subsequence algorithm that works
// on iterator ranges. The implementation below uses the Hirschberg algorithm
// parallelized using a ManagedQueue.

#ifndef VXSIG_LONGEST_COMMON_SUBSEQUENCE_H_
#define VXSIG_LONGEST_COMMON_SUBSEQUENCE_H_

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"

namespace security {
namespace vxsig {

namespace detail {

using LcsRowVector = std::vector<int32_t>;

// Internal function that computes a single row of the LCS length matrix.
template <typename IteratorT>
void ComputeSingleLcsRow(IteratorT first1, IteratorT last1, IteratorT first2,
                         IteratorT last2, LcsRowVector* result) {
  ptrdiff_t size2 = std::distance(first2, last2);
  result->resize(size2 + 1);
  LcsRowVector prev(*result);
  for (auto it1 = first1; it1 != last1; ++it1) {
    prev = *result;
    size_t i = 0;
    for (auto it2 = first2; it2 != last2; ++it2, ++i) {
      (*result)[i + 1] =
          (*it1 == *it2) ? prev[i] + 1 : std::max((*result)[i], prev[i + 1]);
    }
  }
}

// Calculates the longest common subsequence (LCS) of two sequences specified
// by iterator ranges.
//
// This function template calculates the LCS of the elements contained in the
// specified iterator ranges. This implementation uses the Hirschberg algorithm
// and runs in O(n * m) time and O(max(n, m)) space where n and m are the
// lengths of the sequences.
//
// Returns the longest common subsequence of the given sequences in an output
// iterator.
template <typename IteratorT, typename OutputIteratorT>
void LongestCommonSubsequence(IteratorT first1, IteratorT last1,
                              IteratorT first2, IteratorT last2,
                              OutputIteratorT result) {
  using detail::LcsRowVector;
  using detail::ComputeSingleLcsRow;
  using ReverseIteratorT = std::reverse_iterator<IteratorT>;

  // If both sequences have the same prefix, add it to the resulting LCS.
  // This reduces the space needed for the opt array.
  ptrdiff_t size1 = std::distance(first1, last1);
  ptrdiff_t size2 = std::distance(first2, last2);
  while (size1 > 0 && size2 > 0 && *first1 == *first2) {
    *result++ = *first1;
    ++first1;
    ++first2;
    --size1;
    --size2;
  }

  // Empty sequences have an empty longest common subsequence.
  if (size1 == 0 || size2 == 0) {
    return;
  }

  // Optimize for same suffixes.
  auto nlast1 = last1;
  auto nlast2 = last2;
  --nlast1;
  --nlast2;
  while (size1 > 0 && size2 > 0 && *nlast1 == *nlast2) {
    --nlast1;
    --nlast2;
    --size1;
    --size2;
  }
  ++nlast1;
  ++nlast2;

  if (size1 == 1) {
    // Recursion end, simple case with one sequence consisting of one
    // element only.
    auto it = std::find(first2, nlast2, *first1);
    if (it != nlast2) {
      *result++ = *first1;
    }
  } else if (size1 > 1) {
    auto mid1 = first1 + size1 / 2;

    LcsRowVector ll_left;
    LcsRowVector ll_right;

    // If the input size is rather small, avoid the overhead of parallelization.
    // The choice is rather arbitrary, but empirically resulted in good
    // subjective performance.
    if (size1 + size2 > 1000) {
      // TODO(cblichmann): Compute LCS lengths in parallel using OpenMP
      ComputeSingleLcsRow(first1, mid1, first2, nlast2, &ll_left);
      ComputeSingleLcsRow(ReverseIteratorT(nlast1), ReverseIteratorT(mid1),
                          ReverseIteratorT(nlast2), ReverseIteratorT(first2),
                          &ll_right);
    } else {
      // Small input, avoid overhead of ManagedQueue.
      ComputeSingleLcsRow(first1, mid1, first2, nlast2, &ll_left);
      ComputeSingleLcsRow(ReverseIteratorT(nlast1), ReverseIteratorT(mid1),
                          ReverseIteratorT(nlast2), ReverseIteratorT(first2),
                          &ll_right);
    }

    // Divide: Find optimal position where to split the input sequences.
    ptrdiff_t ll_max = -1;
    size_t pivot = 0;
    for (size_t i = 0; i < size2 + 1; ++i) {
      ptrdiff_t ll_cur = ll_left[i] + ll_right[size2 - i];
      if (ll_max < ll_cur) {
        ll_max = ll_cur;
        pivot = i;
      }
    }

    // Conquer: Continue recursively.
    LongestCommonSubsequence(first1, mid1, first2, first2 + pivot, result);
    LongestCommonSubsequence(mid1, nlast1, first2 + pivot, nlast2, result);
  }

  // Add common suffixes to result.
  std::copy(nlast1, last1, result);
}

}  // namespace detail

template <typename IteratorT, typename OutputIteratorT>
void LongestCommonSubsequence(IteratorT first1, IteratorT last1,
                              IteratorT first2, IteratorT last2,
                              OutputIteratorT result) {
  detail::LongestCommonSubsequence(first1, last1, first2, last2, result);
}

// Convenience version of LongestCommonSubsequence() that operates on
// absl::string_view.
std::string LongestCommonSubsequence(absl::string_view first,
                                     absl::string_view second);

}  // namespace vxsig
}  // namespace security

#endif  // VXSIG_LONGEST_COMMON_SUBSEQUENCE_H_
