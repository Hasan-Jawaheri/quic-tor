// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Modified by kku

#ifndef _FILE_UTIL_H_
#define _FILE_UTIL_H_

#include <stdio.h>
#include <string>

FILE* OpenFile(const std::string& filename, const char* mode);

bool CloseFile(FILE* file);

bool ReadFileToString(const std::string& path, std::string* contents,
    size_t max_size);

bool ReadFileToString(const std::string& path, std::string* contents);

#endif /* _FILE_UTIL_H_ */
