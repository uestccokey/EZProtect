//
// Created by like on 2022/1/26.
//

#ifndef MD5_H
#define MD5_H

#define _CRT_SECURE_NO_WARNINGS

#include <string>
#include <cstring>

using std::string;

std::string md5(std::string dat);

std::string md5(const void *dat, size_t len);

std::string md5file(const char *filename);

std::string md5file(std::FILE *file);

#endif // end of MD5_H
