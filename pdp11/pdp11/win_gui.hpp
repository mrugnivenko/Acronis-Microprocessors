#pragma once
#include "defines.hpp"
#include "event_controller.hpp"


const UINT MSG_DRAW = 0x8000;
const WPARAM RUN_BUTTON = 1;
const WPARAM EXIT_BUTTON = 2;
const WPARAM INPUT_BUTTON = 3;
const WPARAM LOAD_EXE_BUTTON = 4;
const WPARAM LOAD_MEM_BUTTON = 5;
const WPARAM LOAD_REGS_BUTTON = 6;
const WPARAM STOP_BUTTON = 7;
const WPARAM RESET_BUTTON = 8;
const WPARAM BREAKPOINT_BUTTON = 9;


extern HWND hScreen;
extern HBITMAP hbmp;

LRESULT CALLBACK WindowProcedure(HWND, UINT, WPARAM, LPARAM);
void add_controls(HWND hWnd);
void DrawPixels(HWND hscr, void *pixels);

void upd_proc_state(const uint16_t regs[8], const status_flags flags, const uint8_t flag_I, const uint16_t bp);
void print_disasm(char str_arr[ROM_size / 2][100]);
void print_memory(char str_arr1[RAM_size / 2][100], char str_arr2[VRAM_size / 2][100], char str_arr3[IO_size / 2][100]);
void print_RAM(char str_arr[RAM_size / 2][100]);
void print_VRAM(char str_arr[VRAM_size / 2][100]);
void print_IO(char str_arr[IO_size / 2][100]);

bool gui_open_file(char *out_str);
