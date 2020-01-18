// Copyright 2011-2020 Google LLC
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

// A function template that, given a number of sequences and a common
// subsequence, builds a regular expression that matches all of the specified
// sequences. This is used to build the final AV signatures in the signature
// generator after common instruction bytes have been found.

#ifndef VXSIG_SUBSEQUENCE_REGEX_H_
#define VXSIG_SUBSEQUENCE_REGEX_H_

#include <algorithm>
#include <cstddef>
#include <functional>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

#include "base/logging.h"

namespace security::vxsig {

// Callback that is used in RegexFromSubsequence() to insert the actual
// wildcards. This allows to insert bounded or unbounded wildcards with the same
// regular expression builder.
template <typename OutputIteratorT>
using WildcardInserter = std::function<void(
    size_t min_qualifier, size_t max_qualifier, OutputIteratorT result)>;

// Builds a regular expression that matches the given common subsequence in each
// of the specified sequences.
template <typename IteratorT, typename NestedContT, typename OutputIteratorT>
void RegexFromSubsequence(IteratorT first, IteratorT last,
                          const NestedContT& sequences,
                          WildcardInserter<OutputIteratorT> wildcard_inserter,
                          OutputIteratorT result) {
  using SequenceIterator = typename NestedContT::value_type::const_iterator;

  // Initialize a vector with search start positions for each sequence.
  std::vector<SequenceIterator> search_starts;
  search_starts.reserve(sequences.size());
  for (const auto& sequence : sequences) {
    search_starts.push_back(sequence.cbegin());
  }

  auto cs_it = first;  // Current position in common subsequence.
  bool insert_wildcard = false;
  bool defer_wildcard = false;
  size_t cont_count = 0;
  while (cs_it != last) {
    // If we are to insert a wildcard, delay insertion until min_cont and
    // max_cont are easily available.
    if (insert_wildcard) {
      defer_wildcard = true;
      insert_wildcard = false;
    }
    // Set sensible defaults for minimum and maximum.
    size_t min_cont = std::distance(last, first);
    size_t max_cont = 0;
    auto search_starts_it = search_starts.begin();
    for (auto it = sequences.cbegin(); it != sequences.cend();
         ++it, ++search_starts_it) {
      SequenceIterator& cur_seq_index = *search_starts_it;

      // Find position of current element in current sequence.
      SequenceIterator search_start = cur_seq_index;
      cur_seq_index = std::find(search_start, it->end(), *cs_it);

      // All sequences must contain all elements from common subsequence in
      // the same order.
      CHECK(cur_seq_index != it->cend());

      // Advance start position for current sequence so we don't look at the
      // same element again in the next iteration.
      ++cur_seq_index;

      // Calculate minimum and maximum number of skipped elements.
      cont_count = cur_seq_index - search_start;
      min_cont = std::min(min_cont, cont_count - 1);
      max_cont = std::max(max_cont, cont_count - 1);

      // Check if elements in current sequence are continuous.
      if (std::distance(cs_it, last) > 1) {
        insert_wildcard = cont_count > 0 && cur_seq_index[0] != cs_it[1];
      }
    }
    if (defer_wildcard) {
      wildcard_inserter(min_cont, max_cont, result++);
      defer_wildcard = false;
    }
    *result++ = *cs_it;
    ++cs_it;
  }
}

}  // namespace security::vxsig

#endif  // VXSIG_SUBSEQUENCE_REGEX_H_
