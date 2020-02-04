#pragma once
#include "defines.hpp"


const int str_amount = int(ROM_size / 2);

const int NWButX = 30;
const int ButGap = 15;

const int R0ID = 10;
const int RegAm = 8;

const int bpDid = 98;
const int bpid = 99;
const int FiFlID = 100;
const int FlAm = 6;

const wchar_t Flags[FlAm][5] = {L"T", L"N", L"Z", L"V", L"C", L"I"};

const int syncID = 22;
const int CaMeID = 23;
const int ConvID = 24;


const int ReID = 25;
const int StID = 26;
const int BrID = 27;

const int ram_list_id = 28;
const int vram_list_id = 29;
const int rom_list_id = 30;
const int io_list_id = 31;

const int getDescrID = 228;

const int max_dasm_str_length = 100;