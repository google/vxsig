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

// Function templates that calculate Hamming distances of iterator ranges,
// element-wise.

#ifndef VXSIG_HAMMING_H_
#define VXSIG_HAMMING_H_

#include <cstddef>
#include <cstdlib>
#include <iterator>
#include <string>

namespace security::vxsig {

// Returns the number of different elements in a specified iterator range.
//
// This function template calculates the Hamming distance of the ranges
// specified by the given input iterators. If the sequences are not of the same
// length, the difference in length is added to the result (i.e., the shorter
// sequence is treated like being padded with a special counting symbol).
template <typename Iterator1T, typename Iterator2T>
size_t HammingDistance(Iterator1T first1, Iterator1T last1, Iterator2T first2,
                       Iterator2T last2) {
  auto result =
      std::abs(std::distance(first2, last2) - std::distance(first1, last1));
  for (; first1 != last1 && first2 != last2; ++first1, ++first2)
    if (!(*first1 == *first2)) {
      ++result;
    }
  return result;
}

// Returns the number of different elements of two sequences in the specified
// standard containers.
template <typename Cont1T, typename Cont2T>
size_t HammingDistance(const Cont1T& first, const Cont2T& second) {
  return HammingDistance(first.begin(), first.end(), second.begin(),
                         second.end());
}

}  // namespace security::vxsig

#endif  // VXSIG_HAMMING_H_
