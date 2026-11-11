#pragma once
#include <stddef.h>
#include <stdint.h>

// Hands the INI bytes that the stubbed FileOpen()/FileReadSec() serve to cfg.cpp.
void mayhem_set_ini(const uint8_t *data, size_t size);
