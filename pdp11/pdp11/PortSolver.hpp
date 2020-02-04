#pragma once
#include "defines.hpp"
#include "includes.hpp"
#include "pdp11lib.hpp"


extern FILE *dbg_log_file;
extern FILE *pdp_log_file;


class PortSolver
{
public:
    PortSolver();
    PortSolver(const PortSolver &solver) = delete;
    PortSolver(PortSolver &&solver) = delete;
    PortSolver &operator=(const PortSolver &solver) = delete;
    PortSolver &operator=(PortSolver &&solver) = delete;

    FILE *fopen(const char *file_name, const char *mode) const;
    FILE *fopen_dbg(const char *file_name, const char *mode) const;
    void fclose(FILE *file) const;
    void fclose_dbg(FILE *file) const;
    size_t get_file_size(FILE *file) const;
    void perror(const char *str) const;
    int fileno(FILE *file) const;
    void dbg_print(const wchar_t *str) const;
};
